use iteron_protocol::{Event, EventKind, RunId, Seq, TenantId, TurnId};
use iteron_record::{Rollout, replay};
use std::alloc::{GlobalAlloc, Layout, System};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

struct TrackingAllocator;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);

fn record_allocation(bytes: usize) {
    let live = LIVE_BYTES.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK_BYTES.fetch_max(live, Ordering::Relaxed);
}

fn record_deallocation(bytes: usize) {
    LIVE_BYTES.fetch_sub(bytes, Ordering::Relaxed);
}

// SAFETY: every operation delegates to `System` with the caller's original pointer/layout. The
// atomics are observation-only bookkeeping and do not participate in allocation.
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: delegated with the exact layout supplied by the allocator caller.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: delegated with the exact layout supplied by the allocator caller.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        record_deallocation(layout.size());
        // SAFETY: delegated with the exact pointer/layout supplied by the allocator caller.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: delegated with the exact pointer/layout supplied by the allocator caller.
        let replacement = unsafe { System.realloc(pointer, layout, new_size) };
        if !replacement.is_null() {
            if new_size >= layout.size() {
                record_allocation(new_size - layout.size());
            } else {
                record_deallocation(layout.size() - new_size);
            }
        }
        replacement
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

static TEMP_ID: AtomicU64 = AtomicU64::new(0);

fn test_directory() -> PathBuf {
    std::env::temp_dir().join(format!(
        "iteron-record-streaming-{}-{}",
        std::process::id(),
        TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ))
}

fn reset_peak() -> usize {
    let baseline = LIVE_BYTES.load(Ordering::SeqCst);
    PEAK_BYTES.store(baseline, Ordering::SeqCst);
    baseline
}

fn peak_growth_since(baseline: usize) -> usize {
    PEAK_BYTES.load(Ordering::SeqCst).saturating_sub(baseline)
}

#[test]
fn d9_11_g2_large_rollout_open_and_replay_do_not_slurp_the_file() {
    const EVENT_COUNT: usize = 12;
    const DECODED_PAYLOAD_BYTES: usize = 512 * 1024;

    let directory = test_directory();
    let run = RunId("large-streamed-rollout".into());
    std::fs::create_dir_all(&directory).unwrap();
    {
        let mut rollout = Rollout::open(&directory, &run, TenantId::default()).unwrap();
        for turn in 0..EVENT_COUNT {
            // NUL is encoded as six JSON bytes. The decoded event set is intentionally much
            // smaller than the physical rollout, making an accidental whole-file read directly
            // visible in the allocator high-water mark.
            //
            // The payload rides on `Done.outcome` rather than on a notice: content-bearing fields
            // are externalized into the content store, so a notice would leave a fixed-size digest
            // marker on the line and the rollout would never get large enough to tell streaming
            // apart from slurping. `done` carries no externalized field, so it stays inline.
            let event = Event {
                seq: Seq::ZERO,
                turn: TurnId(turn as u32),
                kind: EventKind::Done {
                    outcome: "\0".repeat(DECODED_PAYLOAD_BYTES),
                },
            };
            rollout.append(&event).unwrap();
        }
    }
    let path = directory.join("large-streamed-rollout.jsonl");
    let physical_bytes = usize::try_from(std::fs::metadata(&path).unwrap().len()).unwrap();
    assert!(
        physical_bytes > 30 * 1024 * 1024,
        "fixture must be large enough to distinguish streaming from a whole-file allocation"
    );

    let open_baseline = reset_peak();
    let reopened = Rollout::open(&directory, &run, TenantId::default()).unwrap();
    let open_peak_growth = peak_growth_since(open_baseline);
    assert!(
        open_peak_growth < physical_bytes / 2,
        "tail scan allocated {open_peak_growth} bytes for a {physical_bytes}-byte rollout"
    );
    drop(reopened);

    let replay_baseline = reset_peak();
    let events = replay(&path).unwrap();
    let replay_peak_growth = peak_growth_since(replay_baseline);
    assert_eq!(events.len(), EVENT_COUNT);
    assert!(events.iter().all(|event| {
        matches!(
            &event.kind,
            EventKind::Done { outcome } if outcome.len() == DECODED_PAYLOAD_BYTES
        )
    }));
    assert!(
        replay_peak_growth < physical_bytes / 2,
        "streamed replay allocated {replay_peak_growth} bytes for a {physical_bytes}-byte rollout"
    );

    drop(events);
    std::fs::remove_dir_all(directory).ok();
}
