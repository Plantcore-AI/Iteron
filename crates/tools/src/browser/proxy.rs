//! An owned proxy admits only configured origins during an actual bounded browser action.
//! This is browser network routing, not a claim to contain a compromised native browser process.
use super::types::{BrowserConfig, web_url};
use crate::EgressAllowPolicy;
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};

type Egress = Arc<OnceLock<Option<EgressAllowPolicy>>>;
pub(super) struct BrowserProxy {
    pub(super) address: std::net::SocketAddr,
    generation: watch::Sender<u64>,
    next: AtomicU64,
    bytes: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
    worker: tokio::task::JoinHandle<()>,
}
pub(super) struct NetworkLease {
    sender: watch::Sender<u64>,
}
impl Drop for NetworkLease {
    fn drop(&mut self) {
        self.sender.send_replace(0);
    }
}
impl Drop for BrowserProxy {
    fn drop(&mut self) {
        self.generation.send_replace(0);
        self.worker.abort();
    }
}
impl BrowserProxy {
    pub(super) async fn start(
        configuration: BrowserConfig,
        egress: Egress,
    ) -> Result<Self, &'static str> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| "browser_proxy_unavailable")?;
        let address = listener
            .local_addr()
            .map_err(|_| "browser_proxy_unavailable")?;
        let (generation, _) = watch::channel(0u64);
        let receiver = generation.subscribe();
        let bytes = Arc::new(AtomicUsize::new(0));
        let traffic = bytes.clone();
        let requests = Arc::new(AtomicUsize::new(0));
        let accepted = requests.clone();
        let worker = tokio::spawn(async move {
            let capacity = Arc::new(Semaphore::new(8));
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                let mut receiver = receiver.clone();
                let expected = *receiver.borrow_and_update();
                let permit = capacity.clone().try_acquire_owned();
                if expected == 0
                    || permit.is_err()
                    || accepted.fetch_add(1, Ordering::AcqRel) >= 256
                {
                    drop(socket);
                    continue;
                }
                let configuration = configuration.clone();
                let receiver = receiver.clone();
                let egress = egress.clone();
                let bytes = traffic.clone();
                let permit = permit.expect("checked permit");
                tokio::spawn(async move {
                    let mut changed = receiver.clone();
                    let operation =
                        forward(socket, configuration, egress, receiver, expected, bytes);
                    tokio::select! {
                        biased;
                        _=changed.changed()=>{},
                        _=tokio::time::sleep(Duration::from_secs(45))=>{},
                        _=operation=>{},
                    }
                    drop(permit);
                });
            }
        });
        Ok(Self {
            address,
            generation,
            next: AtomicU64::new(1),
            bytes,
            requests,
            worker,
        })
    }
    pub(super) fn activate(&self) -> Result<NetworkLease, &'static str> {
        let next = self
            .next
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                old.checked_add(1)
            })
            .map_err(|_| "browser_network_epoch_exhausted")?;
        self.bytes.store(0, Ordering::Release);
        self.requests.store(0, Ordering::Release);
        self.generation.send_replace(next);
        Ok(NetworkLease {
            sender: self.generation.clone(),
        })
    }
}
async fn forward(
    mut inbound: TcpStream,
    configuration: BrowserConfig,
    egress: Egress,
    generation: watch::Receiver<u64>,
    expected: u64,
    traffic: Arc<AtomicUsize>,
) -> Result<(), ()> {
    let mut header = Vec::new();
    loop {
        if header.len() >= 16 * 1024 {
            return Err(());
        }
        let mut byte = [0u8; 1];
        tokio::time::timeout(Duration::from_secs(2), inbound.read_exact(&mut byte))
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = std::str::from_utf8(&header).map_err(|_| ())?;
    let first = text.split("\r\n").next().ok_or(())?;
    let words = first.split_whitespace().collect::<Vec<_>>();
    if words.len() != 3 || !matches!(words[2], "HTTP/1.1" | "HTTP/1.0") {
        return Err(());
    }
    let tunnel = words[0] == "CONNECT";
    let url = web_url(&if tunnel {
        format!("https://{}/", words[1])
    } else {
        words[1].to_owned()
    })
    .map_err(|_| ())?;
    let raw_host = url.host_str().ok_or(())?;
    let host = raw_host.trim_matches(['[', ']']);
    let port = url.port_or_known_default().ok_or(())?;
    if !configuration.permits(&url) || *generation.borrow() != expected {
        return Err(());
    }
    match egress.get() {
        Some(Some(policy)) if !policy.permits(host, Some(port)) => return Err(()),
        None => return Err(()),
        _ => {}
    }
    let resolved = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())?
    .take(17)
    .collect::<Vec<_>>();
    if resolved.is_empty() || resolved.len() > 16 {
        return Err(());
    }
    // Internal test/application origins require an explicit IP literal, never DNS rebinding.
    let literal = host
        .trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()
        .ok();
    if resolved
        .iter()
        .any(|address| private(address.ip()) && literal != Some(address.ip()))
    {
        return Err(());
    }
    if *generation.borrow() != expected {
        return Err(());
    }
    let mut outbound = tokio::time::timeout(
        Duration::from_secs(3),
        TcpStream::connect(resolved.as_slice()),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())?;
    if tunnel {
        inbound
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .map_err(|_| ())?;
    } else {
        let path = match url.query() {
            Some(query) => format!("{}?{}", url.path(), query),
            None => url.path().to_owned(),
        };
        let mut rewritten = format!(
            "{} {path} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n",
            words[0], raw_host, port
        );
        for line in text.split("\r\n").skip(1).filter(|line| !line.is_empty()) {
            let (key, _) = line.split_once(':').ok_or(())?;
            if !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return Err(());
            }
            if !matches!(
                key.to_ascii_lowercase().as_str(),
                "host" | "connection" | "proxy-connection" | "proxy-authorization"
            ) {
                rewritten.push_str(line);
                rewritten.push_str("\r\n");
            }
        }
        rewritten.push_str("\r\n");
        outbound
            .write_all(rewritten.as_bytes())
            .await
            .map_err(|_| ())?;
    }
    let (read_in, write_in) = inbound.split();
    let (read_out, write_out) = outbound.split();
    let upstream = copy_bounded(read_in, write_out, traffic.clone());
    let downstream = copy_bounded(read_out, write_in, traffic);
    tokio::try_join!(upstream, downstream)?;
    Ok(())
}
async fn copy_bounded(
    mut reader: impl tokio::io::AsyncRead + Unpin,
    mut writer: impl tokio::io::AsyncWrite + Unpin,
    traffic: Arc<AtomicUsize>,
) -> Result<(), ()> {
    let mut local = 0usize;
    let mut buffer = [0u8; 8192];
    loop {
        let count = reader.read(&mut buffer).await.map_err(|_| ())?;
        if count == 0 {
            writer.shutdown().await.map_err(|_| ())?;
            return Ok(());
        }
        local = local.saturating_add(count);
        let total = traffic
            .fetch_add(count, Ordering::AcqRel)
            .saturating_add(count);
        if local > 8 * 1024 * 1024 || total > 64 * 1024 * 1024 {
            return Err(());
        }
        writer.write_all(&buffer[..count]).await.map_err(|_| ())?;
    }
}
fn private(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast()
        }
        std::net::IpAddr::V6(ip) => {
            ip.to_ipv4_mapped()
                .is_some_and(|mapped| private(std::net::IpAddr::V4(mapped)))
                || ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
        }
    }
}
