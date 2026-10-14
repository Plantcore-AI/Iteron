//! The explicit `serve` process owns the backend. Clients hold no process handle, Agent or writer.
//! A disconnect never sends drain/stop. This owner exists only on the explicitly selected service path.
use crate::app_server::{AppServerClient, SubmitError};
use iteron_protocol::resident_service::{
    RESIDENT_SERVICE_VERSION, ResidentServiceCommandV1, ResidentServiceScopeV1,
    ResidentServiceViewV1,
};
use iteron_protocol::{Op, SessionId, TenantId};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::watch;

pub(crate) struct ResidentService {
    scope: ResidentServiceScopeV1,
    endpoint: SocketAddr,
    stop: watch::Sender<bool>,
    stopping: Mutex<bool>,
    drain: Arc<AtomicBool>,
}
impl ResidentService {
    /// Inputs are captured by the actual host attachment, not accepted from a wire command.
    pub(crate) fn bind(
        thread_id: SessionId,
        tenant: TenantId,
        canonical_workspace: &Path,
        endpoint: SocketAddr,
        drain: Arc<AtomicBool>,
    ) -> Result<Self, &'static str> {
        if !endpoint.ip().is_loopback() || endpoint.port() == 0 {
            return Err("service endpoint is not bound loopback");
        }
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| "service identity entropy unavailable")?;
        let service_id = nonce.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let mut commitment = Sha256::new();
        commitment.update(b"iteron-resident-workspace-v1\0");
        commitment.update(canonical_workspace.as_os_str().as_encoded_bytes());
        let scope = ResidentServiceScopeV1 {
            service_id,
            thread_id,
            tenant,
            workspace_sha256: format!("{:x}", commitment.finalize()),
        };
        scope.validate()?;
        let (stop, _) = watch::channel(false);
        Ok(Self {
            scope,
            endpoint,
            stop,
            stopping: Mutex::new(false),
            drain,
        })
    }
    pub(crate) fn subscribe_stop(&self) -> watch::Receiver<bool> {
        self.stop.subscribe()
    }
    pub(crate) fn stopping(&self) -> bool {
        *self
            .stopping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    pub(crate) fn service_id(&self) -> &str {
        &self.scope.service_id
    }
    pub(crate) fn command(
        &self,
        client: &AppServerClient,
        command: ResidentServiceCommandV1,
    ) -> PreparedServiceReply {
        let Some(current) = client.thread_snapshot_v1() else {
            return PreparedServiceReply::refused("unavailable");
        };
        if current.thread_id != self.scope.thread_id {
            return PreparedServiceReply::refused("scope_changed");
        }
        let mut stopping = self
            .stopping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match command {
            ResidentServiceCommandV1::Read {} => PreparedServiceReply::read(
                json!({"type":"resident_service_v1","service":ResidentServiceViewV1 {
                version:RESIDENT_SERVICE_VERSION,scope:self.scope.clone(),endpoint:self.endpoint,
                current_run_id:current.run_id,stopping:*stopping,shutdown_completed:false }}),
            ),
            ResidentServiceCommandV1::Stop { scope } => {
                if scope.validate().is_err() || scope != self.scope {
                    return PreparedServiceReply::refused("scope_mismatch");
                }
                if *stopping {
                    return PreparedServiceReply::read(
                        json!({"type":"resident_service_stop_v1","service_id":self.scope.service_id,"status":"already_requested","shutdown_completed":false}),
                    );
                }
                let submission = match client.submit_identified(Op::Drain) {
                    Ok(id) => id,
                    Err(SubmitError::Busy) => return PreparedServiceReply::refused("busy"),
                    Err(_) => return PreparedServiceReply::refused("unavailable"),
                };
                self.drain.store(true, Ordering::Release);
                *stopping = true;
                PreparedServiceReply {
                    value: json!({"type":"resident_service_stop_v1","service_id":self.scope.service_id,"status":"requested","submission_id":submission,"shutdown_completed":false}),
                    stop: Some(self.stop.clone()),
                }
            }
        }
    }
}
/// Only a real accepted host command can mint this signal. The transport holds it until its
/// bounded reply attempt finishes; observer loss/drop still activates the already admitted stop.
/// No serialized response can construct or deserialize this object.
pub(crate) struct PreparedServiceReply {
    pub(crate) value: Value,
    stop: Option<watch::Sender<bool>>,
}
impl PreparedServiceReply {
    fn read(value: Value) -> Self {
        Self { value, stop: None }
    }
    fn refused(code: &'static str) -> Self {
        Self::read(json!({"type":"resident_service_refused_v1","reason_code":code}))
    }
}
impl Drop for PreparedServiceReply {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop.send_replace(true);
        }
    }
}
