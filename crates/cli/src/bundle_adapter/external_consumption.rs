use super::schema::CoreSlot;
use iteron_marketplace::ProcessLaunchPlan;
use iteron_tunables::ModuleId;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const SCHEMA: &str = "iteron-implementation-consumption/1";
static NEXT_WRITE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
pub(super) enum Stage {
    Begin,
    Loaded,
    Started,
    Terminal,
    Stopped,
}

pub(super) struct ConsumptionLedger {
    path: PathBuf,
    document: Mutex<ConsumptionDocument>,
}

impl ConsumptionLedger {
    pub(super) fn new(
        runs_dir: &Path,
        candidate_sha256: &str,
        activation_sha256: &str,
        cli_run_id: &str,
        resolved: &[(ModuleId, CoreSlot, ProcessLaunchPlan)],
    ) -> Result<Arc<Self>, ()> {
        std::fs::create_dir_all(runs_dir).map_err(|_| ())?;
        let document = ConsumptionDocument {
            schema_id: SCHEMA.to_owned(),
            candidate_sha256: candidate_sha256.to_owned(),
            activation_sha256: activation_sha256.to_owned(),
            cli_run_id: cli_run_id.to_owned(),
            implementations: resolved
                .iter()
                .map(|(module, _, plan)| ConsumptionRow {
                    module: *module,
                    implementation_id: plan.implementation_id().to_owned(),
                    loaded: false,
                    started: false,
                    terminal: false,
                    stopped: false,
                })
                .collect(),
        };
        let ledger = Arc::new(Self {
            path: runs_dir.join(format!(
                ".iteron-implementation-{activation_sha256}-consumption.json"
            )),
            document: Mutex::new(document),
        });
        {
            let document = ledger.document.lock().map_err(|_| ())?;
            ledger.write_locked(&document)?;
        }
        Ok(ledger)
    }

    pub(super) fn record(&self, module: ModuleId, stage: Stage) -> Result<(), ()> {
        let mut document = self.document.lock().map_err(|_| ())?;
        let row = document
            .implementations
            .iter_mut()
            .find(|row| row.module == module)
            .ok_or(())?;
        match stage {
            Stage::Begin => {
                row.loaded = false;
                row.started = false;
                row.terminal = false;
                row.stopped = false;
            }
            Stage::Loaded => row.loaded = true,
            Stage::Started if row.loaded => row.started = true,
            Stage::Terminal if row.started => row.terminal = true,
            Stage::Stopped if row.loaded => row.stopped = true,
            _ => return Err(()),
        }
        self.write_locked(&document)
    }

    fn write_locked(&self, document: &ConsumptionDocument) -> Result<(), ()> {
        let bytes = serde_json::to_vec_pretty(document).map_err(|_| ())?;
        let temp = self.path.with_extension(format!(
            "json.tmp-{}-{}",
            std::process::id(),
            NEXT_WRITE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&temp).map_err(|_| ())?;
        let result = (|| {
            file.write_all(&bytes).map_err(|_| ())?;
            file.sync_all().map_err(|_| ())?;
            std::fs::rename(&temp, &self.path).map_err(|_| ())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        result
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumptionDocument {
    schema_id: String,
    candidate_sha256: String,
    activation_sha256: String,
    cli_run_id: String,
    implementations: Vec<ConsumptionRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumptionRow {
    module: ModuleId,
    implementation_id: String,
    loaded: bool,
    started: bool,
    terminal: bool,
    stopped: bool,
}
