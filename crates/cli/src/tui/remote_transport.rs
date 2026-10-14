//! Authenticated client transport. It owns one socket and finite presentation buffers, no runtime.
use anyhow::{Context, Result, bail};
use base64::Engine as _;
use iteron_protocol::PROTOCOL_VERSION;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{
    TcpStream,
    tcp::{OwnedReadHalf, OwnedWriteHalf},
};
use tokio::time::Instant;
use zeroize::Zeroizing;

const MAX_FRAME_BYTES: usize = 1024 * 1024;
const MAX_LOGICAL_BYTES: usize = 8 * 1024 * 1024;
const MAX_COMMAND_BYTES: usize = 512 * 1024;
const IO_DEADLINE: Duration = Duration::from_secs(5);
const ASSEMBLY_DEADLINE: Duration = Duration::from_secs(30);

struct CommandBytes(Zeroizing<Vec<u8>>);
impl std::io::Write for CommandBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > MAX_COMMAND_BYTES {
            return Err(std::io::Error::other(
                "remote command exceeds its finite transport bound",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) struct Transport {
    reader: Reader,
    writer: OwnedWriteHalf,
    next_request: u64,
    pub(super) thread: iteron_protocol::SessionId,
}
pub(super) struct Reader {
    source: BufReader<OwnedReadHalf>,
    pending: Vec<u8>,
    fragment: Option<Fragment>,
    partial_started: Option<Instant>,
}
struct Fragment {
    stream: String,
    logical_type: String,
    seq: Option<u64>,
    rollout_seq: Option<u64>,
    bytes: Vec<u8>,
    expected_bytes: usize,
    next: u64,
    chunks: u64,
    deadline: Instant,
}
impl Transport {
    pub(super) async fn connect(endpoint: SocketAddr) -> Result<Self> {
        if !endpoint.ip().is_loopback() || endpoint.port() == 0 {
            bail!("attach requires a bound loopback service endpoint");
        }
        let token = super::headless::auth::read_from_stdin().await?;
        let socket = tokio::time::timeout(IO_DEADLINE, TcpStream::connect(endpoint))
            .await
            .context("service connection timed out")??;
        let (source, mut writer) = socket.into_split();
        let hello = token.client_hello();
        tokio::time::timeout(IO_DEADLINE, writer.write_all(&hello))
            .await
            .context("service handshake write timed out")??;
        drop(token);
        drop(hello);
        let mut reader = Reader {
            source: BufReader::with_capacity(8192, source),
            pending: Vec::new(),
            fragment: None,
            partial_started: None,
        };
        let hello = tokio::time::timeout(IO_DEADLINE, reader.next())
            .await
            .context("service handshake timed out")??
            .context("service closed before handshake")?;
        if hello["type"] != "hello"
            || hello["product_contract_version"]
                != iteron_protocol::product_contract::PRODUCT_CONTRACT_VERSION
        {
            bail!("service refused the current client contract");
        }
        let thread = hello["session_id"]
            .as_str()
            .filter(|v| !v.is_empty() && v.len() <= 256 && !v.chars().any(char::is_control))
            .context("service thread identity unavailable")?;
        Ok(Self {
            reader,
            writer,
            next_request: 1,
            thread: iteron_protocol::SessionId(thread.to_owned()),
        })
    }
    pub(super) async fn control(&mut self, control: Value) -> Result<u64> {
        let id = self.next_request;
        self.next_request = id
            .checked_add(1)
            .context("client request identity exhausted")?;
        let frame = json!({"type":"control","protocol_version":PROTOCOL_VERSION,"request_id":id,"control":control});
        let mut bytes = CommandBytes(Zeroizing::new(Vec::new()));
        serde_json::to_writer(&mut bytes, &frame)?;
        bytes.0.push(b'\n');
        tokio::time::timeout(IO_DEADLINE, self.writer.write_all(&bytes.0))
            .await
            .context("service command write timed out; delivery is unknown")??;
        Ok(id)
    }
    pub(super) async fn next(&mut self) -> Result<Option<Value>> {
        self.reader.next().await
    }
}
impl Reader {
    pub(super) async fn next(&mut self) -> Result<Option<Value>> {
        loop {
            let deadline = self
                .fragment
                .as_ref()
                .map(|v| v.deadline)
                .or(self.partial_started.map(|at| at + ASSEMBLY_DEADLINE));
            let available = if let Some(deadline) = deadline {
                tokio::time::timeout_at(deadline, self.source.fill_buf())
                    .await
                    .context("partial service frame timed out")??
            } else {
                self.source.fill_buf().await?
            };
            if available.is_empty() {
                if !self.pending.is_empty() || self.fragment.is_some() {
                    bail!("service closed during a partial frame; observation is incomplete");
                }
                return Ok(None);
            }
            let newline = available.iter().position(|b| *b == b'\n');
            let take = newline.map_or(available.len(), |at| at + 1);
            if self.pending.len().saturating_add(take) > MAX_FRAME_BYTES + 1 {
                bail!("service frame exceeds its byte bound");
            }
            if self.partial_started.is_none() {
                self.partial_started = Some(Instant::now());
            }
            self.pending.extend_from_slice(&available[..take]);
            self.source.consume(take);
            if newline.is_none() {
                continue;
            }
            let frame: Value =
                serde_json::from_slice(&self.pending).context("invalid service frame")?;
            self.pending.clear();
            self.partial_started = None;
            if frame["protocol_version"] != PROTOCOL_VERSION {
                bail!("service protocol changed after handshake");
            }
            if frame["type"] == "frame_chunk" {
                if let Some(frame) = self.chunk(frame)? {
                    return Ok(Some(frame));
                }
                continue;
            }
            if self.fragment.is_some() {
                bail!("service interleaved a fragmented logical frame");
            }
            return Ok(Some(frame));
        }
    }
    fn chunk(&mut self, frame: Value) -> Result<Option<Value>> {
        let bytes = frame["logical_bytes"]
            .as_u64()
            .filter(|v| *v > 0 && *v <= MAX_LOGICAL_BYTES as u64)
            .context("logical frame exceeds the bounded view; use artifact paging")?
            as usize;
        let chunks = frame["chunk_count"]
            .as_u64()
            .filter(|v| *v > 0 && *v <= 32)
            .context("invalid fragment count")?;
        let index = frame["chunk_index"]
            .as_u64()
            .context("invalid fragment index")?;
        let stream = frame["stream"]
            .as_str()
            .filter(|v| matches!(*v, "live" | "control" | "rollout"))
            .context("invalid fragment stream")?;
        let logical_type = frame["logical_type"]
            .as_str()
            .filter(|v| matches!(*v, "event" | "result" | "control_reply" | "rollout"))
            .context("unsupported fragmented service view")?;
        if frame["encoding"] != "base64" {
            bail!("unsupported service fragment encoding");
        }
        let seq = frame["seq"].as_u64();
        let rollout_seq = frame["rollout_seq"].as_u64();
        if self.fragment.is_none() {
            if index != 0 {
                bail!("fragmented view did not begin at zero");
            }
            self.fragment = Some(Fragment {
                stream: stream.into(),
                logical_type: logical_type.into(),
                seq,
                rollout_seq,
                bytes: Vec::with_capacity(bytes.min(MAX_FRAME_BYTES)),
                expected_bytes: bytes,
                next: 0,
                chunks,
                deadline: Instant::now() + ASSEMBLY_DEADLINE,
            });
        }
        let current = self.fragment.as_mut().expect("installed above");
        if current.stream != stream
            || current.logical_type != logical_type
            || current.seq != seq
            || current.rollout_seq != rollout_seq
            || current.expected_bytes != bytes
            || current.chunks != chunks
            || current.next != index
            || index >= chunks
        {
            bail!("service fragment identity or order changed");
        }
        let encoded = frame["data"]
            .as_str()
            .context("fragment bytes unavailable")?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .context("invalid fragment bytes")?;
        if current.bytes.len().saturating_add(decoded.len()) > current.expected_bytes {
            bail!("service fragments exceed their claimed byte count");
        }
        current.bytes.extend_from_slice(&decoded);
        current.next += 1;
        if current.next < chunks {
            return Ok(None);
        }
        let complete = self.fragment.take().expect("installed above");
        if complete.bytes.len() != bytes {
            bail!("service fragment byte count does not match");
        }
        let value: Value = serde_json::from_slice(&complete.bytes)?;
        if value["type"] != complete.logical_type
            || value["protocol_version"] != PROTOCOL_VERSION
            || value["seq"].as_u64() != seq
            || value["rollout_seq"].as_u64() != rollout_seq
        {
            bail!("assembled service frame lost its source identity");
        }
        Ok(Some(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    async fn pair() -> (Reader, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let connect = TcpStream::connect(listener.local_addr().unwrap());
        let (client, accepted) = tokio::join!(connect, listener.accept());
        let (source, _writer) = client.unwrap().into_split();
        (
            Reader {
                source: BufReader::new(source),
                pending: Vec::new(),
                fragment: None,
                partial_started: None,
            },
            accepted.unwrap().0,
        )
    }
    fn chunk(payload: &[u8], index: u64, count: u64, total: usize) -> Vec<u8> {
        let value = json!({"type":"frame_chunk","protocol_version":PROTOCOL_VERSION,"stream":"control","logical_type":"control_reply","logical_bytes":total,"chunk_count":count,"chunk_index":index,"encoding":"base64","data":base64::engine::general_purpose::STANDARD.encode(payload)});
        let mut encoded = serde_json::to_vec(&value).unwrap();
        encoded.push(b'\n');
        encoded
    }
    #[tokio::test]
    async fn socket_fragments_join_only_the_same_declared_identity_and_complete_byte_count() {
        let (mut reader, mut server) = pair().await;
        let expected = json!({"type":"control_reply","protocol_version":PROTOCOL_VERSION,"request_id":13,"reply":{"type":"observation","body":"actual socket bytes"}});
        let bytes = serde_json::to_vec(&expected).unwrap();
        let split = bytes.len() / 2;
        server
            .write_all(&chunk(&bytes[..split], 0, 2, bytes.len()))
            .await
            .unwrap();
        server
            .write_all(&chunk(&bytes[split..], 1, 2, bytes.len()))
            .await
            .unwrap();
        assert_eq!(reader.next().await.unwrap(), Some(expected));
        drop(server);
        assert!(reader.next().await.unwrap().is_none());
        let (mut reader, mut server) = pair().await;
        server
            .write_all(&chunk(&bytes[..split], 0, 2, bytes.len()))
            .await
            .unwrap();
        server
            .write_all(&chunk(&bytes[split..], 0, 2, bytes.len()))
            .await
            .unwrap();
        assert!(
            reader.next().await.is_err(),
            "duplicate chunk cannot become an observation"
        );
    }
    #[tokio::test]
    async fn cancelling_a_partial_socket_read_keeps_bytes_and_command_serialization_is_bounded_before_copy()
     {
        let (mut reader, mut server) = pair().await;
        let value = json!({"type":"control_reply","protocol_version":PROTOCOL_VERSION,"request_id":1,"reply":{"actual":true}});
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        server.write_all(&bytes[..8]).await.unwrap();
        let deadline = Instant::now() + Duration::from_millis(50);
        assert!(
            tokio::time::timeout_at(deadline, reader.next())
                .await
                .is_err()
        );
        assert_eq!(
            reader.pending,
            &bytes[..8],
            "already consumed physical bytes survive observer cancellation"
        );
        server.write_all(&bytes[8..]).await.unwrap();
        assert_eq!(reader.next().await.unwrap(), Some(value));
        let mut sink = CommandBytes(Zeroizing::new(Vec::new()));
        assert!(
            serde_json::to_writer(&mut sink, &json!({"text":"x".repeat(MAX_COMMAND_BYTES+1)}))
                .is_err()
        );
        assert!(sink.0.len() <= MAX_COMMAND_BYTES);
    }
}
