//! Exact subprocess ownership and joined owner-drop cleanup.

use std::collections::HashMap;
use std::future::{Future as _, poll_fn};
use std::io;
use std::process::ExitStatus;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::Duration;

#[derive(Default)]
struct ProcessState {
    closing: bool,
    next_registration: u64,
    children: HashMap<u64, tokio::process::Child>,
}

/// Spawn/reap authority shared by every subprocess owned by one effect supervisor.
///
/// The registry owns each `Child`, not merely its reusable numeric pid. A caller receives an opaque
/// ticket for pipes, signalling, and waiting. Both an ordinary cancel-safe wait poll and emergency
/// owner-drop remove the exact child under the same mutex, so there is no interval in which one
/// path can reap a process and the other can signal a newly reused pid.
#[derive(Clone, Default)]
pub(in crate::tui) struct ProcessRegistry(Arc<Mutex<ProcessState>>);

/// Non-cloneable authority for one child stored in [`ProcessRegistry`]. Dropping a live ticket
/// synchronously kills and joins that exact stored `Child`.
pub(in crate::tui) struct RegisteredChild {
    registry: ProcessRegistry,
    registration: u64,
    #[cfg(all(test, unix))]
    pid: Option<u32>,
    active: bool,
}

impl ProcessRegistry {
    fn lock(&self) -> MutexGuard<'_, ProcessState> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(in crate::tui) fn spawn(
        &self,
        command: &mut tokio::process::Command,
    ) -> io::Result<RegisteredChild> {
        let mut state = self.lock();
        if state.closing {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "effect supervisor is closing",
            ));
        }
        let registration = state.next_registration;
        state.next_registration = state.next_registration.checked_add(1).ok_or_else(|| {
            io::Error::other("effect child registration space has been exhausted")
        })?;
        // The registry, rather than Tokio's drop guard, owns kill-and-join. This is essential: a
        // late `kill_on_drop` would contain only a numeric pid after emergency wait had reaped it.
        command.kill_on_drop(false);
        let child = command.spawn()?;
        #[cfg(all(test, unix))]
        let pid = child.id();
        state.children.insert(registration, child);
        Ok(RegisteredChild {
            registry: self.clone(),
            registration,
            #[cfg(all(test, unix))]
            pid,
            active: true,
        })
    }

    fn poll_wait(
        &self,
        registration: u64,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<ExitStatus>> {
        let mut state = self.lock();
        let polled = {
            let Some(child) = state.children.get_mut(&registration) else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "effect child ownership was already settled",
                )));
            };
            let mut wait = Box::pin(child.wait());
            wait.as_mut().poll(context)
        };
        if matches!(&polled, Poll::Ready(Ok(_))) {
            state.children.remove(&registration);
        }
        polled
    }

    fn reap_registration(&self, registration: u64) -> bool {
        let mut state = self.lock();
        let Some(child) = state.children.remove(&registration) else {
            return false;
        };
        // Keep the ownership mutex through physical join. `Supervisor::drop` therefore cannot see
        // an empty registry and return while a ticket is still reaping the claimed child.
        kill_and_join(child);
        drop(state);
        true
    }

    /// Close the spawn gate, take exclusive ownership of every remaining child, and synchronously
    /// kill and join them before returning. Returning the count makes the exclusivity invariant
    /// directly testable without observing or signalling a numeric pid.
    pub(in crate::tui) fn close_and_reap(&self) -> usize {
        let mut state = self.lock();
        state.closing = true;
        let children = std::mem::take(&mut state.children);
        let count = children.len();
        for (_, child) in children {
            kill_and_join(child);
        }
        // A concurrent ticket cleanup uses this same lock through physical join, so acquiring it
        // was also a join barrier for a child it had already claimed.
        drop(state);
        count
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(in crate::tui) fn is_empty(&self) -> bool {
        self.lock().children.is_empty()
    }
}

impl RegisteredChild {
    #[cfg(all(test, unix))]
    pub(in crate::tui) fn id(&self) -> Option<u32> {
        self.active.then_some(self.pid).flatten()
    }

    pub(in crate::tui) fn take_stdin(&mut self) -> Option<tokio::process::ChildStdin> {
        self.registry
            .lock()
            .children
            .get_mut(&self.registration)
            .and_then(|child| child.stdin.take())
    }

    #[cfg(target_os = "linux")]
    pub(in crate::tui) fn take_stdout(&mut self) -> Option<tokio::process::ChildStdout> {
        self.registry
            .lock()
            .children
            .get_mut(&self.registration)
            .and_then(|child| child.stdout.take())
    }

    pub(in crate::tui) fn start_kill(&mut self) -> io::Result<()> {
        let mut state = self.registry.lock();
        match state.children.get_mut(&self.registration) {
            Some(child) => child.start_kill(),
            None => Ok(()),
        }
    }

    pub(in crate::tui) async fn wait(&mut self) -> io::Result<ExitStatus> {
        let registry = self.registry.clone();
        let registration = self.registration;
        let result = poll_fn(move |context| registry.poll_wait(registration, context)).await;
        if result.is_ok() {
            self.active = false;
        }
        result
    }

    /// Emergency ownership transfer used after an async wait deadline or wait error. Only one of
    /// this method, normal wait completion, or supervisor close can take the stored child.
    pub(in crate::tui) fn reap_sync(&mut self) -> bool {
        if !self.active {
            return false;
        }
        self.active = false;
        self.registry.reap_registration(self.registration)
    }

    #[cfg(all(test, unix))]
    fn try_wait_with_ready_hook(
        &mut self,
        ready_hook: &mut dyn FnMut(),
    ) -> io::Result<Option<ExitStatus>> {
        let mut state = self.registry.lock();
        let Some(child) = state.children.get_mut(&self.registration) else {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "effect child ownership was already settled",
            ));
        };
        let status = child.try_wait()?;
        if status.is_some() {
            // The adversarial test pauses exactly after OS reap and before map removal. The mutex
            // must keep emergency cleanup from acquiring any stale numeric identity here.
            ready_hook();
            state.children.remove(&self.registration);
            self.active = false;
        }
        Ok(status)
    }
}

impl Drop for RegisteredChild {
    fn drop(&mut self) {
        self.reap_sync();
    }
}

fn kill_and_join(mut child: tokio::process::Child) {
    let _ = child.start_kill();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => std::thread::sleep(Duration::from_millis(1)),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            // Exclusive ownership makes `ECHILD`/invalid-handle impossible in a conforming
            // implementation. Retry rather than returning across an unjoined ownership boundary.
            Err(_) => std::thread::sleep(Duration::from_millis(1)),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::process::Stdio;
    use std::sync::{Barrier, mpsc};

    fn sleep_command(seconds: &str) -> tokio::process::Command {
        let mut command = tokio::process::Command::new("/bin/sleep");
        command
            .arg(seconds)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    #[tokio::test]
    async fn ready_wait_and_emergency_close_have_one_exclusive_child_owner() {
        let registry = ProcessRegistry::default();
        let mut command = tokio::process::Command::new("/bin/sh");
        command
            .args(["-c", "exit 0"])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = registry.spawn(&mut command).expect("spawn short child");
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let mut hook = || {
                ready_tx.send(()).expect("announce exact reap gap");
                release_rx.recv().expect("release exact reap gap");
            };
            loop {
                if child
                    .try_wait_with_ready_hook(&mut hook)
                    .expect("coordinated try_wait")
                    .is_some()
                {
                    return;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        });

        ready_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("waiter reached post-reap critical section");
        let closer_registry = registry.clone();
        let (attempted_tx, attempted_rx) = mpsc::channel();
        let (closed_tx, closed_rx) = mpsc::channel();
        let closer = std::thread::spawn(move || {
            attempted_tx.send(()).expect("announce close attempt");
            closed_tx
                .send(closer_registry.close_and_reap())
                .expect("report close count");
        });
        attempted_rx
            .recv()
            .expect("closer attempted ownership lock");
        release_tx.send(()).expect("release waiter");
        waiter.join().expect("waiter thread");
        assert_eq!(
            closed_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            0,
            "normal wait removed the child before emergency close acquired ownership"
        );
        closer.join().expect("closer thread");
    }

    #[tokio::test]
    async fn close_claims_one_pending_wait_child_and_joins_before_return() {
        let registry = ProcessRegistry::default();
        let mut command = sleep_command("30");
        let child = registry.spawn(&mut command).expect("spawn pending child");
        let pid = child.id().expect("pending child pid") as libc::pid_t;
        let registration = child.registration;
        let lock_registry = registry.clone();
        let (pending_tx, pending_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let waiter_poll = std::thread::spawn(move || {
            let mut state = lock_registry.lock();
            assert!(
                state
                    .children
                    .get_mut(&registration)
                    .expect("registered child")
                    .try_wait()
                    .unwrap()
                    .is_none()
            );
            pending_tx.send(()).expect("announce pending poll");
            release_rx.recv().expect("release pending poll");
            drop(state);
        });
        pending_rx.recv().expect("wait poll holds ownership mutex");
        let close_registry = registry.clone();
        let (attempted_tx, attempted_rx) = mpsc::channel();
        let closer = std::thread::spawn(move || {
            attempted_tx.send(()).expect("announce close attempt");
            close_registry.close_and_reap()
        });
        attempted_rx.recv().expect("close attempted ownership");
        release_tx.send(()).expect("release pending poll");
        waiter_poll.join().expect("pending poll thread");
        assert_eq!(closer.join().expect("close thread"), 1);
        drop(child);
        // SAFETY: signal 0 observes only whether the exact just-joined child still exists.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    }

    #[tokio::test]
    async fn timeout_fallback_and_owner_close_have_exactly_one_child_claimant() {
        let registry = ProcessRegistry::default();
        let mut command = sleep_command("30");
        let mut child = registry.spawn(&mut command).expect("spawn raced child");
        let barrier = Arc::new(Barrier::new(3));
        let ticket_barrier = barrier.clone();
        let ticket = std::thread::spawn(move || {
            ticket_barrier.wait();
            child.reap_sync()
        });
        let close_registry = registry.clone();
        let close_barrier = barrier.clone();
        let closer = std::thread::spawn(move || {
            close_barrier.wait();
            close_registry.close_and_reap()
        });
        barrier.wait();
        let ticket_claimed = usize::from(ticket.join().expect("ticket reaper"));
        let close_claimed = closer.join().expect("owner close");
        assert_eq!(ticket_claimed + close_claimed, 1);
    }

    #[tokio::test]
    async fn stale_ticket_with_reused_diagnostic_pid_cannot_touch_new_registration() {
        let registry = ProcessRegistry::default();
        let mut first_command = tokio::process::Command::new("/bin/sh");
        first_command
            .args(["-c", "exit 0"])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut first = registry
            .spawn(&mut first_command)
            .expect("spawn first registration");
        let stale_registration = first.registration;
        first.wait().await.expect("reap first registration");

        let mut second_command = sleep_command("30");
        let mut second = registry
            .spawn(&mut second_command)
            .expect("spawn second registration");
        assert_ne!(stale_registration, second.registration);
        let mut stale_ticket = RegisteredChild {
            registry: registry.clone(),
            registration: stale_registration,
            // Deliberately give the stale ticket the live child's diagnostic pid. Cleanup must
            // ignore it and authorize solely by the opaque, non-reused registration.
            pid: second.pid,
            active: true,
        };
        assert!(!stale_ticket.reap_sync());
        assert!(registry.lock().children.contains_key(&second.registration));
        assert!(second.reap_sync());
    }
}
