//! Real Windows file capability and registered confined language-server journeys.
use super::*;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

struct Workspace(PathBuf);
impl Workspace {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "iteron-windows-lsp-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::create_dir(path.join("src")).unwrap();
        std::fs::write(path.join("src/main.rs"), "a😀b\nfn main() {}\n").unwrap();
        Self(path)
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn routes() -> BTreeMap<String, LspLanguageRoute> {
    LspRuntimePolicy::default().by_language()
}

#[tokio::test]
async fn native_windows_lsp_source_retains_bytes_identity_and_utf16_positions() {
    let root = Workspace::new("source");
    let document = SourceDocument::load(&root.0, "src/main.rs", &routes())
        .await
        .unwrap();
    assert_eq!(document.text(), "a😀b\nfn main() {}\n");
    assert!(
        document
            .root_capability()
            .unwrap()
            .metadata()
            .unwrap()
            .is_dir()
    );
    assert_eq!(document.root(), root.0.canonicalize().unwrap());
    assert!(document.uri().ends_with("/src/main.rs"));
    assert!(document.position(0, 4).is_ok());
    assert!(document.position(0, 2).is_err());
    document.recheck().await.unwrap();
    // The source File denies write/delete sharing, and its actual ancestors deny delete sharing.
    assert!(std::fs::write(root.0.join("src/main.rs"), b"replacement").is_err());
    assert!(std::fs::remove_file(root.0.join("src/main.rs")).is_err());
    assert!(std::fs::rename(root.0.join("src"), root.0.join("renamed")).is_err());
    document.recheck().await.unwrap();
    drop(document);
    std::fs::write(root.0.join("src/main.rs"), b"replacement").unwrap();
    std::fs::rename(root.0.join("src"), root.0.join("renamed")).unwrap();
    assert_eq!(
        std::fs::read(root.0.join("renamed/main.rs")).unwrap(),
        b"replacement"
    );
}

#[tokio::test]
async fn native_windows_lsp_source_refuses_escape_stream_and_oversize() {
    let root = Workspace::new("refusal");
    for requested in ["../outside.rs", "src/main.rs:alternate", "NUL.rs", "src"] {
        assert!(
            SourceDocument::load(&root.0, requested, &routes())
                .await
                .is_err(),
            "{requested}"
        );
    }
    let oversized = root.0.join("src/large.rs");
    std::fs::write(&oversized, vec![b'x'; input::MAX_SOURCE_BYTES + 1]).unwrap();
    assert!(matches!(
        SourceDocument::load(&root.0, "src/large.rs", &routes()).await,
        Err(LspToolError::SourceTooLarge { .. })
    ));
    std::fs::write(root.0.join("src/bad.rs"), [0xff]).unwrap();
    assert!(matches!(
        SourceDocument::load(&root.0, "src/bad.rs", &routes()).await,
        Err(LspToolError::SourceNotUtf8)
    ));
    assert!(!root.0.join("server-ran").exists());
}

#[tokio::test]
async fn native_windows_lsp_source_never_follows_a_reparse_leaf_or_root() {
    let root = Workspace::new("reparse");
    let outside = Workspace::new("outside");
    std::os::windows::fs::symlink_file(outside.0.join("src/main.rs"), root.0.join("link.rs"))
        .unwrap();
    assert!(
        SourceDocument::load(&root.0, "link.rs", &routes())
            .await
            .is_err()
    );
    let linked_root = root.0.join("linked-root");
    std::os::windows::fs::symlink_dir(&outside.0, &linked_root).unwrap();
    assert!(
        SourceDocument::load(&linked_root, "src/main.rs", &routes())
            .await
            .is_err()
    );
    // The original physical source is unchanged; denial is not an empty or substituted source.
    assert_eq!(
        std::fs::read(outside.0.join("src/main.rs")).unwrap(),
        "a😀b\nfn main() {}\n".as_bytes()
    );
}

const SERVER: &str = r#"
$ErrorActionPreference = 'Stop'
$inputStream = [Console]::OpenStandardInput()
$outputStream = [Console]::OpenStandardOutput()
$trace = Join-Path $PSScriptRoot 'server-ran'
function Read-Frame {
    $header = [Collections.Generic.List[byte]]::new()
    for ($i=0; $i -lt 8192; $i++) {
        $b = $inputStream.ReadByte()
        if ($b -lt 0) { return $null }
        $header.Add([byte]$b)
        if ($header.Count -ge 4) {
            $tail = [Text.Encoding]::ASCII.GetString($header.ToArray(), $header.Count-4, 4)
            if ($tail -eq "`r`n`r`n") { break }
        }
    }
    $text = [Text.Encoding]::ASCII.GetString($header.ToArray())
    if ($text -notmatch '^Content-Length: ([0-9]+)\r\n\r\n$') { throw 'invalid header' }
    $length = [int]$Matches[1]
    if ($length -lt 1 -or $length -gt 65536) { throw 'invalid body length' }
    $body = [byte[]]::new($length)
    for ($read=0; $read -lt $length;) {
        $n=$inputStream.Read($body, $read, $length-$read)
        if ($n -lt 1) { throw 'incomplete body' }
        $read += $n
    }
    return ([Text.Encoding]::UTF8.GetString($body) | ConvertFrom-Json)
}
function Reply($id, $result) {
    $json = @{ jsonrpc='2.0'; id=$id; result=$result } | ConvertTo-Json -Depth 8 -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    $header = [Text.Encoding]::ASCII.GetBytes("Content-Length: $($bytes.Length)`r`n`r`n")
    $outputStream.Write($header, 0, $header.Length)
    $outputStream.Write($bytes, 0, $bytes.Length)
    $outputStream.Flush()
}
for ($request=0; $request -lt 16; $request++) {
    $message = Read-Frame
    if ($null -eq $message) { exit 0 }
    [IO.File]::AppendAllText($trace, "$($message.method)`n")
    switch ($message.method) {
        'initialize' { Reply $message.id @{ capabilities=@{ positionEncoding='utf-16'; hoverProvider=$true } } }
        'textDocument/hover' { Reply $message.id @{ contents=@{ kind='plaintext'; value='actual native Windows LSP' } } }
        'shutdown' { Reply $message.id $null }
        'exit' { exit 0 }
        default { if ($null -ne $message.id) { throw 'unexpected method' } }
    }
}
throw 'request bound exhausted'
"#;

fn native_route(root: &Path) -> Vec<LanguageServerRoute> {
    vec![LanguageServerRoute {
        language: "rust".into(),
        command: vec![
            "powershell.exe".into(),
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-ExecutionPolicy".into(),
            "Bypass".into(),
            "-File".into(),
            root.join("fixture-server.ps1").to_str().unwrap().into(),
        ],
    }]
}

#[tokio::test]
async fn native_windows_registered_lsp_uses_real_confined_pipes_reuse_and_cleanup() {
    let root = Workspace::new("registered");
    std::fs::write(root.0.join("fixture-server.ps1"), SERVER).unwrap();
    let registry = Registry::coding_agent_with_lsp_routes(&root.0, native_route(&root.0)).unwrap();
    let control = registry.lsp_control().unwrap();
    assert_eq!(
        registry.capability_of("lsp_query"),
        Some(Capability::CodeExecuting)
    );
    for index in 0..2 {
        let result = tokio::time::timeout(
            Duration::from_secs(35),
            registry.run(ToolUse {
                id: format!("native-lsp-{index}"),
                name: "lsp_query".into(),
                input: json!({"query":"hover", "path":"src/main.rs", "line":0, "character":4}),
            }),
        )
        .await
        .unwrap();
        assert!(
            !result.is_error,
            "actual native LSP must run: {}",
            result.content
        );
        assert_eq!(result.trust, Trust::Untrusted);
        let output: Value = serde_json::from_str(&result.content).unwrap();
        assert_eq!(output["target_freshness_rechecked"], true);
        assert_eq!(output["server_reused"], index != 0);
        assert_eq!(output["result"]["text"], "actual native Windows LSP");
        assert_eq!(output["backend"], "windows-lpac-pipes");
        assert!(!result.content.contains(root.0.to_str().unwrap()));
    }
    let cleanup = tokio::time::timeout(Duration::from_secs(10), control.clean())
        .await
        .unwrap();
    assert_eq!(cleanup.len(), 1);
    assert!(
        cleanup[0].1,
        "native wait/Job0/isolation retirement must be observed"
    );
    let methods = std::fs::read_to_string(root.0.join("server-ran")).unwrap();
    assert_eq!(
        methods.lines().filter(|line| *line == "initialize").count(),
        1
    );
    assert_eq!(
        methods
            .lines()
            .filter(|line| *line == "textDocument/hover")
            .count(),
        2
    );
    assert_eq!(
        methods.lines().filter(|line| *line == "shutdown").count(),
        1
    );
    assert_eq!(methods.lines().filter(|line| *line == "exit").count(), 1);
    let health = control.health().await;
    assert_eq!(health.running_servers, 0);
    assert_eq!(health.unknown_slots, 0);
}
