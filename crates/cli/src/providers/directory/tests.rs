use super::super::cache_storage::prepare_private_cache_directory;
use super::super::discovery::ProviderRefreshActivity;
use super::super::instance_factory::catalog_configuration;
use super::super::*;
use iteron_provider::catalog::glm_standard_schema_catalog;
use iteron_provider::{ApiRoot, BalanceAvailability, CredentialSource, ProviderHealth};
use iteron_provider::{ModelDescriptor, ModelFamily, RawModel};
use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

static CACHE_TEST_ID: AtomicU64 = AtomicU64::new(0);

fn test_cache_path(label: &str) -> PathBuf {
    let id = CACHE_TEST_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir()
        .join(format!(
            "iteron-provider-cache-{label}-{}-{id}",
            std::process::id()
        ))
        .join(CATALOG_CACHE_FILE)
}

fn remove_test_cache(path: &Path) {
    if let Some(parent) = path.parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

fn spawn_json_server(body: String) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = Vec::new();
        let mut chunk = [0_u8; 2_048];
        loop {
            let read = stream.read(&mut chunk).unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            assert!(request.len() < 16 * 1024);
        }
        write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body,
            )
            .unwrap();
        stream.flush().unwrap();
    });
    (format!("http://{address}/v1"), handle)
}

fn spawn_counting_json_server(body: String) -> (String, Arc<AtomicU64>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicU64::new(0));
    let observed = Arc::clone(&accepts);
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        observed.fetch_add(1, Ordering::SeqCst);
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = Vec::new();
        let mut chunk = [0_u8; 2_048];
        loop {
            let read = stream.read(&mut chunk).unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            assert!(request.len() < 16 * 1024);
        }
        write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body,
            )
            .unwrap();
        stream.flush().unwrap();
    });
    (format!("http://{address}/v1"), accepts, handle)
}

fn closed_api_root() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    format!("http://{address}/v1")
}

/// An endpoint that is reachable and then silent: the kernel completes the handshake from the
/// listener's backlog, so `connect` succeeds and the request waits for a response that never
/// comes. This is the shape that used to hold a whole launch for the 15 s discovery deadline.
/// The returned listener must stay alive for the duration of the test.
fn black_hole_api_root() -> (String, TcpListener) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    (format!("http://{address}/v1"), listener)
}

fn offline_entry(id: &str, adapter: AdapterKind, catalog_enabled: bool) -> ProviderEntry {
    ProviderEntry {
        instance: ProviderInstance::new(
            id,
            id,
            adapter,
            ApiRoot::parse("http://127.0.0.1:9/v1").unwrap(),
            None,
        )
        .unwrap(),
        credential: ProviderCredential::Env {
            name: format!("{id}_KEY").to_ascii_uppercase(),
        },
        origin: ProviderOrigin::OperatorConfigured,
        credential_present: false,
        enabled: true,
        catalog_enabled,
        catalog: None,
        catalog_error: None,
        catalog_fallback_explicit: false,
        catalog_stale: false,
        declared_capabilities: BTreeMap::new(),
        catalog_provenance: CatalogProvenance::Unavailable,
    }
}

fn glm_static_entry(credential: Option<String>) -> ProviderEntry {
    glm_static_entry_with_metadata(credential, StaticProviderMetadata::embedded())
}

fn glm_static_entry_with_metadata(
    credential: Option<String>,
    metadata: Arc<StaticProviderMetadata>,
) -> ProviderEntry {
    let instance = ProviderInstance::new(
        "glm",
        "GLM / 智谱",
        AdapterKind::OpenAiCompatibleChat,
        ApiRoot::parse(metadata.glm_api_root()).unwrap(),
        credential,
    )
    .unwrap()
    .with_static_metadata(metadata.clone());
    let (catalog_enabled, _) = catalog_configuration(&instance, true);
    let catalog = Some(glm_standard_schema_catalog(&instance).unwrap());
    let credential_present = instance.has_credential();
    ProviderEntry {
        instance,
        credential: ProviderCredential::Env {
            name: "GLM_API_KEY".into(),
        },
        origin: ProviderOrigin::Builtin,
        credential_present,
        enabled: true,
        catalog_enabled,
        catalog,
        catalog_error: None,
        catalog_fallback_explicit: false,
        catalog_stale: false,
        declared_capabilities: BTreeMap::new(),
        catalog_provenance: CatalogProvenance::StaticOfficial {
            version: metadata.glm_catalog_version().into(),
            source: metadata.glm_catalog_source().into(),
        },
    }
}

/// A build-time default cannot know which account the machine has. `first_credentialed_provider`
/// answers the question that constant was standing in for, using local credential presence
/// only, so it is safe to call before any discovery and cannot depend on the network.
#[tokio::test]
async fn the_first_credentialed_provider_is_the_one_that_can_authenticate() {
    let none = ProviderDirectory::discover_entries(vec![glm_static_entry(None)], None)
        .await
        .unwrap();
    assert_eq!(none.first_credentialed_provider(), None);
    assert!(!none.has_credential("glm"));
    assert!(
        !none.has_credential("a-provider-that-does-not-exist"),
        "an unknown id has no credential rather than panicking"
    );

    let some =
        ProviderDirectory::discover_entries(vec![glm_static_entry(Some("sk-1".into()))], None)
            .await
            .unwrap();
    assert_eq!(some.first_credentialed_provider(), Some("glm"));
    assert!(some.has_credential("glm"));
}

/// With nothing credentialed anywhere, the failure is a setup step, not a fault of whichever
/// provider the build-time fallback happened to name. It still has to name that provider's own
/// remedy, because that is the one the operator is looking at.
#[tokio::test]
async fn an_uncredentialed_machine_is_told_it_is_a_setup_step() {
    let directory = ProviderDirectory::discover_entries(vec![glm_static_entry(None)], None)
        .await
        .unwrap();
    let message = directory.resolution_error("glm");
    assert!(message.contains("setup step"), "{message}");
    assert!(message.contains("GLM_API_KEY"), "{message}");
    assert!(message.contains("iteron setup --byok glm"), "{message}");
    assert!(
        message.contains("--stdin"),
        "the terminal-free form must be reachable from the error: {message}"
    );
}

fn policy_entry_with_credential(
    id: &str,
    api_root: &str,
    credential: Option<&str>,
) -> ProviderEntry {
    let instance = ProviderInstance::new(
        id,
        id,
        AdapterKind::OpenAiCompatibleChat,
        ApiRoot::parse(api_root).unwrap(),
        credential.map(str::to_owned),
    )
    .unwrap();
    let (catalog_enabled, catalog_error) = catalog_configuration(&instance, true);
    let credential_present = instance.has_credential();
    ProviderEntry {
        instance,
        credential: ProviderCredential::Env {
            name: format!("{}_KEY", id.to_ascii_uppercase()),
        },
        origin: ProviderOrigin::OperatorConfigured,
        credential_present,
        enabled: true,
        catalog_enabled,
        catalog: None,
        catalog_error,
        catalog_fallback_explicit: false,
        catalog_stale: false,
        declared_capabilities: BTreeMap::new(),
        catalog_provenance: CatalogProvenance::Unavailable,
    }
}

fn policy_entry(id: &str, api_root: &str) -> ProviderEntry {
    policy_entry_with_credential(id, api_root, Some("test-key"))
}

fn descriptor(
    id: &str,
    compatibility: Compatibility,
    selectability: Selectability,
) -> ModelDescriptor {
    ModelDescriptor {
        raw: RawModel {
            id: id.into(),
            display_name: Some(id.into()),
            created_at: None,
            owned_by: None,
            supports_image_input: None,
        },
        family_id: "other".into(),
        compatibility,
        selectability,
    }
}

fn snapshot(provider_id: &str, models: Vec<ModelDescriptor>) -> CatalogSnapshot {
    CatalogSnapshot {
        provider_instance_id: provider_id.into(),
        adapter: AdapterKind::OpenAiCompatibleChat,
        families: vec![ModelFamily {
            id: "other".into(),
            display_name: "Other / unclassified".into(),
            models: models.clone(),
        }],
        models,
    }
}

fn catalogued_entry(id: &str, api_root: &str, model_id: &str) -> ProviderEntry {
    let mut entry = policy_entry(id, api_root);
    entry.catalog = Some(snapshot(
        id,
        vec![descriptor(
            model_id,
            Compatibility::Compatible,
            Selectability::Selectable,
        )],
    ));
    entry.catalog_provenance = CatalogProvenance::DynamicFresh;
    entry
}

#[test]
fn public_inventory_freezes_catalog_and_resolves_only_matching_host_route_identities() {
    use iteron_protocol::client_inventory::{
        ClientInventoryKindV1, ClientInventoryQueryV1, ClientModelSelectionV1,
    };
    let entry = catalogued_entry(
        "inventory-fixture",
        "https://provider.example.invalid/v1",
        "model-a",
    );
    let health = ProviderHealthStore::new(4);
    health.mark_ready(entry.id());
    let mut directory = ProviderDirectory {
        entries: Arc::new(vec![entry]),
        health,
        deferred: None,
        refresh_activity: ProviderRefreshActivity::default(),
    };
    let selected = ModelSelection {
        provider_id: "inventory-fixture".into(),
        model_id: "model-a".into(),
    };
    let native_digests = directory.selection_digests(&selected);
    let owner = crate::client_inventory::ClientInventoryOwner::capture(
        &directory,
        &crate::plugin_runtime::RuntimePlugins::default(),
        &selected,
    )
    .unwrap();
    let query = ClientInventoryQueryV1 {
        kind: ClientInventoryKindV1::Models,
        provider_id: None,
        offset: 0,
        limit: 1,
    };
    let before = owner.read(&query).unwrap();
    let record = &before["records"][0];
    let mut request = ClientModelSelectionV1 {
        inventory_digest_sha256: owner.digest(),
        provider_id: selected.provider_id.clone(),
        model_id: selected.model_id.clone(),
        catalog_digest_sha256: record["catalog_digest_sha256"].as_str().unwrap().into(),
        capability_digest_sha256: record["capability_digest_sha256"].as_str().unwrap().into(),
    };
    request.validate().unwrap();
    assert_eq!(request.catalog_digest_sha256.len(), 64);
    assert_eq!(request.capability_digest_sha256.len(), 64);
    let resolved = owner.resolve(&request).unwrap();
    assert_eq!(resolved.provider_id, selected.provider_id);
    assert_eq!(resolved.catalog_digest, native_digests.0);
    assert_eq!(resolved.capability_digest, native_digests.1);
    assert_eq!(
        resolved.catalog_digest,
        format!("sha256:{}", request.catalog_digest_sha256)
    );
    assert_eq!(
        resolved.capability_digest,
        format!("sha256:{}", request.capability_digest_sha256)
    );
    let mut tagged_wire_request = request.clone();
    tagged_wire_request.catalog_digest_sha256 = resolved.catalog_digest;
    assert!(tagged_wire_request.validate().is_err());
    assert!(owner.resolve(&tagged_wire_request).is_err());
    Arc::make_mut(&mut directory.entries)[0].catalog = Some(snapshot(
        "inventory-fixture",
        vec![descriptor(
            "new-model",
            Compatibility::Compatible,
            Selectability::Selectable,
        )],
    ));
    assert_eq!(
        owner.read(&query).unwrap(),
        before,
        "mutable discovery does not replace captured evidence"
    );
    request.capability_digest_sha256 = "0".repeat(64);
    assert!(owner.resolve(&request).is_err());
    request.model_id = "new-model".into();
    assert!(owner.resolve(&request).is_err());
    let text = before.to_string();
    assert!(!text.contains("provider.example.invalid"));
    assert!(!text.contains("test-key"));
}

fn test_scope_key(path: &Path) -> CatalogCacheScopeKey {
    CatalogCacheScopeKey::load_or_create(path).unwrap()
}

fn seed_cache(path: &Path, entry: &ProviderEntry) {
    let scope_key = test_scope_key(path);
    let mut cache = CatalogCache::default();
    assert!(cache.upsert(entry, &scope_key));
    cache.save_atomic(path).unwrap();
}

/// I-46. A cache-format bump renames the file, so every earlier generation kept sitting in
/// `~/.iteron/cache/providers` holding a full stale catalog nobody reads. Writing the current
/// generation reclaims them, and touches nothing else in the directory.
#[test]
fn d11_46_writing_the_current_catalog_cache_reclaims_the_superseded_one() {
    let path = test_cache_path("supersede");
    let parent = path.parent().unwrap().to_path_buf();
    fs::create_dir_all(&parent).unwrap();
    let stale = parent.join("catalogs-v1.json");
    fs::write(&stale, b"{\"version\":1,\"entries\":[]}").unwrap();
    let unrelated = parent.join("something-else.json");
    fs::write(&unrelated, b"{}").unwrap();

    let source = catalogued_entry("supersede", "https://gateway.example/v1/", "gpt-4o-mini");
    seed_cache(&path, &source);

    assert!(path.is_file(), "the current generation is written");
    assert!(
        !stale.exists(),
        "the superseded generation must not sit beside it forever"
    );
    assert!(
        unrelated.exists(),
        "only Iteron's own superseded caches are reclaimed"
    );
    remove_test_cache(&path);
}

#[test]
fn catalog_cache_round_trips_atomically_without_credentials_or_errors() {
    let path = test_cache_path("round-trip");
    let mut source = catalogued_entry("cache-test", "https://gateway.example/v1/", "gpt-4o-mini");
    source.catalog.as_mut().unwrap().models[0]
        .raw
        .supports_image_input = Some(true);
    source.catalog.as_mut().unwrap().families[0].models[0]
        .raw
        .supports_image_input = Some(true);
    let disabled = descriptor(
        "zzz-unknown",
        Compatibility::Unknown,
        Selectability::Disabled {
            reason: "coding-turn compatibility is unknown",
        },
    );
    source
        .catalog
        .as_mut()
        .unwrap()
        .models
        .push(disabled.clone());
    source.catalog.as_mut().unwrap().families[0]
        .models
        .push(disabled);
    source.catalog_error = Some("raw-error-with-test-key".into());
    seed_cache(&path, &source);

    let bytes = fs::read(&path).unwrap();
    assert!(bytes.len() <= MAX_CATALOG_CACHE_BYTES);
    let text = String::from_utf8(bytes).unwrap();
    assert!(
        !text.contains("test-key"),
        "credentials must never be cached"
    );
    assert!(
        !text.contains("raw-error"),
        "raw errors must never be cached"
    );
    let naked_credential_hash = {
        let bytes = Sha256::digest(b"test-key");
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    assert!(
        !text.contains(&naked_credential_hash),
        "a naked credential hash must never be cached"
    );
    assert!(text.contains(CATALOG_CACHE_SCOPE_PREFIX));
    let key_bytes = fs::read(path.parent().unwrap().join(CATALOG_CACHE_SCOPE_KEY_FILE)).unwrap();
    assert_eq!(key_bytes.len(), CATALOG_CACHE_SCOPE_KEY_BYTES);
    assert!(
        !key_bytes
            .windows(b"test-key".len())
            .any(|window| window == b"test-key"),
        "the local scope key must not contain the provider credential"
    );
    assert_eq!(
        fs::read_dir(path.parent().unwrap()).unwrap().count(),
        2,
        "atomic temporary files must not remain after commit"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(path.parent().unwrap().join(CATALOG_CACHE_SCOPE_KEY_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    let loaded = CatalogCache::load(&path);
    assert_eq!(loaded.fixture_version(), CATALOG_CACHE_VERSION);
    let scope_key = test_scope_key(&path);
    let snapshot = loaded.lookup(&source, &scope_key).unwrap();
    assert_eq!(snapshot, source.catalog.clone().unwrap());
    assert_eq!(snapshot.models[0].raw.id, "gpt-4o-mini");
    assert_eq!(snapshot.models[0].raw.supports_image_input, Some(true));
    assert_eq!(snapshot.models[0].selectability, Selectability::Selectable);

    let wrong_root = policy_entry("cache-test", "https://other.example/v1");
    assert!(
        loaded.lookup(&wrong_root, &scope_key).is_none(),
        "provider id alone must never cross an API-root/strategy boundary"
    );
    remove_test_cache(&path);
}

#[test]
fn catalog_cache_rejects_wrong_versions_corruption_and_all_hard_bounds() {
    let path = test_cache_path("bounds");
    fs::create_dir_all(path.parent().unwrap()).unwrap();

    fs::write(&path, br#"{"version":999,"entries":[]}"#).unwrap();
    assert!(CatalogCache::load(&path).fixture_entries().is_empty());
    fs::write(&path, b"{not-json").unwrap();
    assert!(CatalogCache::load(&path).fixture_entries().is_empty());
    fs::write(&path, vec![b' '; MAX_CATALOG_CACHE_BYTES + 1]).unwrap();
    assert!(CatalogCache::load(&path).fixture_entries().is_empty());

    let source = catalogued_entry("cache-bounds", "https://gateway.example/v1", "gpt-4o-mini");
    let scope_key = test_scope_key(&path);
    let cached = CachedCatalog::from_entry(&source, &scope_key).unwrap();
    let too_many_entries = CatalogCache::fixture_parts(
        CATALOG_CACHE_VERSION,
        vec![cached.clone(); MAX_CATALOG_CACHE_ENTRIES + 1],
    );
    assert!(!too_many_entries.is_valid());

    let mut too_many_models = cached.clone();
    too_many_models.families[0].models = (0..=MAX_CACHED_MODELS_PER_ENTRY)
        .map(|index| CachedModel {
            id: format!("model-{index}"),
            display_name: None,
            created_at: None,
            owned_by: None,
            supports_image_input: None,
            compatibility: CachedCompatibility::Compatible,
            selectability: CachedSelectability::Selectable,
        })
        .collect();
    assert!(!too_many_models.is_valid());

    let mut expired = cached.clone();
    expired.fetched_at_unix_secs = current_unix_secs()
        .unwrap()
        .saturating_sub(CATALOG_CACHE_TTL_SECS + 1);
    let expired_cache = CatalogCache::fixture_parts(CATALOG_CACHE_VERSION, vec![expired]);
    assert!(expired_cache.lookup(&source, &scope_key).is_none());

    let mut wrong_classifier = cached;
    wrong_classifier.classifier_version += 1;
    assert!(!wrong_classifier.is_valid());
    remove_test_cache(&path);
}

#[cfg(unix)]
#[test]
fn catalog_cache_scope_key_rejects_symlinks() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let path = test_cache_path("scope-key-symlink");
    prepare_private_cache_directory(path.parent().unwrap()).unwrap();
    let target = path.parent().unwrap().join("untrusted-key-target");
    fs::write(&target, [7_u8; CATALOG_CACHE_SCOPE_KEY_BYTES]).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(
        &target,
        path.parent().unwrap().join(CATALOG_CACHE_SCOPE_KEY_FILE),
    )
    .unwrap();

    assert!(CatalogCacheScopeKey::load_or_create(&path).is_err());
    remove_test_cache(&path);
}

#[test]
fn d13_13_rng_unavailable_is_unsupported_without_a_weak_fallback_key() {
    let path = test_cache_path("unsupported-rng");
    let error = CatalogCacheScopeKey::load_or_create_with_rng(&path, |_| {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "test target has no admitted OS CSPRNG",
        ))
    })
    .err()
    .expect("an unsupported RNG must disable persistent catalog caching");

    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    assert!(
        !path
            .parent()
            .unwrap()
            .join(CATALOG_CACHE_SCOPE_KEY_FILE)
            .exists(),
        "time, pid, and temporary-file nonces must never become fallback key material"
    );
    remove_test_cache(&path);
}

#[tokio::test]
async fn d13_13_fresh_cache_serves_a_second_run_without_rediscovery() {
    let path = test_cache_path("refresh");
    let body = serde_json::json!({
        "data": [{"id": "gpt-4o-mini", "owned_by": "openai"}]
    })
    .to_string();
    let (api_root, server) = spawn_json_server(body);
    let target = policy_entry("refresh-test", &api_root);

    let directory = ProviderDirectory::discover_entries(vec![target.clone()], Some(path.clone()))
        .await
        .unwrap();
    // The fixture accepts exactly one request and then exits. Any second discovery attempt
    // therefore fails closed instead of accidentally making this a cache-hit-shaped test.
    server.join().unwrap();
    let refreshed = directory.entry("refresh-test").unwrap();
    assert!(!refreshed.catalog_stale);
    assert_eq!(
        refreshed.catalog.as_ref().unwrap().models[0].raw.id,
        "gpt-4o-mini"
    );
    let scope_key = test_scope_key(&path);
    assert!(
        CatalogCache::load(&path)
            .lookup(refreshed, &scope_key)
            .is_some()
    );

    let second = ProviderDirectory::discover_entries(vec![target], Some(path.clone()))
        .await
        .unwrap();
    let cached = second.entry("refresh-test").unwrap();
    assert_eq!(cached.catalog_provenance, CatalogProvenance::CachedFresh);
    assert!(!cached.catalog_stale);
    assert!(cached.catalog_error.is_none());
    assert_eq!(
        second
            .resolve_model("gpt-4o-mini", Some("refresh-test"))
            .unwrap(),
        ModelSelection {
            provider_id: "refresh-test".into(),
            model_id: "gpt-4o-mini".into(),
        }
    );
    remove_test_cache(&path);
}

#[tokio::test]
async fn a_launch_paints_before_any_provider_network_settles() {
    // Five configured providers, all of them black holes. Discovery used to await providers
    // before the first byte was printed, so one unreachable entry bought a 15 s black screen.
    // The canonical eager budget is now exactly zero: even the selected route refreshes behind
    // first paint unless local cache/static evidence already resolves it.
    // A responding fixture is incorrect here: zero eager budget means nobody is required to
    // connect before this assertion, so joining its blocking `accept` thread can hang a passing
    // test. A live silent listener proves the stronger property without an unpolled server.
    let (api_root, routed_listener) = black_hole_api_root();
    let mut entries = vec![policy_entry("routed", &api_root)];
    let mut listeners = vec![routed_listener];
    for index in 0..4 {
        let (root, listener) = black_hole_api_root();
        listeners.push(listener);
        entries.push(policy_entry(&format!("unused-{index}"), &root));
    }

    let started = std::time::Instant::now();
    let directory =
        ProviderDirectory::discover_entries_eagerly(entries, None, Some(&["routed".into()]))
            .await
            .unwrap();
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(5),
        "a black-holed endpoint delayed the first frame by {elapsed:?}"
    );
    assert_eq!(
        directory
            .entry("routed")
            .and_then(|entry| entry.catalog.as_ref())
            .map(|catalog| catalog.models[0].raw.id.as_str()),
        None,
        "first paint must not adopt a provider response that arrived after its zero budget"
    );
    assert!(
        directory.deferred.is_some(),
        "the unreachable providers must still be outstanding, not silently dropped"
    );
    for index in 0..4 {
        assert!(
            directory
                .entry(&format!("unused-{index}"))
                .expect("every configured instance is still listed")
                .catalog
                .is_none(),
            "an unresolved provider must not appear resolved"
        );
    }
    // Configured order is the operator's order and must survive concurrent completion.
    assert_eq!(
        directory
            .entries()
            .iter()
            .map(ProviderEntry::id)
            .collect::<Vec<_>>(),
        ["routed", "unused-0", "unused-1", "unused-2", "unused-3"]
    );
    drop(listeners);
}

#[tokio::test]
async fn deferred_discovery_accepts_zero_connections_until_post_paint_settle_signal() {
    let body = serde_json::json!({ "data": [{ "id": "after-paint-model" }] }).to_string();
    let (api_root, accepts, server) = spawn_counting_json_server(body);
    let mut directory = ProviderDirectory::discover_entries_eagerly(
        vec![policy_entry("after-paint", &api_root)],
        None,
        Some(&["after-paint".into()]),
    )
    .await
    .unwrap();

    // Give an accidentally spawned task ample scheduling time. A dormant discovery owns no
    // future that Tokio can poll, so the loopback listener must still see exactly zero accepts.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        0,
        "directory construction must make zero provider-network connections"
    );

    assert!(
        directory.settle().await,
        "post-paint settlement should land"
    );
    server.join().unwrap();
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
    assert_eq!(
        directory
            .entry("after-paint")
            .and_then(|entry| entry.catalog.as_ref())
            .map(|catalog| catalog.models[0].raw.id.as_str()),
        Some("after-paint-model")
    );
}

#[tokio::test]
async fn host_first_frame_publishes_discovery_and_factory_from_the_same_admitted_inventory() {
    use iteron_protocol::client_inventory::{
        ClientInventoryKindV1, ClientInventoryQueryV1, ClientModelSelectionV1,
    };
    let body = serde_json::json!({"data":[{"id":"host-discovered-model"}]}).to_string();
    let (api_root, accepts, server) = spawn_counting_json_server(body);
    let directory = ProviderDirectory::discover_entries_eagerly(
        vec![policy_entry("host-discovery", &api_root)],
        None,
        Some(&["host-discovery".into()]),
    )
    .await
    .unwrap();
    let selected = ModelSelection {
        provider_id: "host-discovery".into(),
        model_id: "host-discovered-model".into(),
    };
    let owner = crate::client_inventory::ClientInventoryOwner::capture(
        &directory,
        &crate::plugin_runtime::RuntimePlugins::default(),
        &selected,
    )
    .unwrap();
    let mut observer = owner.catalog_subscription();
    let before = observer.current();
    assert!(before.discovery_pending());
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        0,
        "a readonly view does not start native discovery"
    );
    owner.first_frame().unwrap();
    let after = tokio::time::timeout(Duration::from_secs(3), observer.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(!after.discovery_pending());
    assert!(
        before.discovery_pending(),
        "published views remain immutable"
    );
    let page = owner
        .read(&ClientInventoryQueryV1 {
            kind: ClientInventoryKindV1::Models,
            provider_id: None,
            offset: 0,
            limit: 25,
        })
        .unwrap();
    assert_eq!(page["inventory_digest_sha256"], after.inventory_digest());
    let (catalog, capability) = after.selection_digests(&selected);
    let request = ClientModelSelectionV1 {
        inventory_digest_sha256: after.inventory_digest().into(),
        provider_id: selected.provider_id.clone(),
        model_id: selected.model_id.clone(),
        catalog_digest_sha256: catalog,
        capability_digest_sha256: capability,
    };
    assert!(owner.resolve(&request).is_ok());
    assert!(
        owner
            .session_directory()
            .validate_selection(&selected, true)
            .is_ok()
    );
    let mut old_request = request;
    old_request.inventory_digest_sha256 = before.inventory_digest().into();
    assert!(owner.resolve(&old_request).is_err());
    owner.first_frame().unwrap();
    server.join().unwrap();
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        1,
        "all first-frame callers share the actual single refresh"
    );
    assert!(!format!("{after:?}").contains("test-key"));
}

#[tokio::test]
async fn host_refuses_invalid_discovery_without_leaving_pending_or_installing_its_route() {
    use iteron_protocol::client_inventory::{ClientInventoryKindV1, ClientInventoryQueryV1};
    let invalid_model = "x".repeat(513);
    let body = serde_json::json!({"data":[{"id":invalid_model}]}).to_string();
    let (api_root, accepts, server) = spawn_counting_json_server(body);
    let directory = ProviderDirectory::discover_entries_eagerly(
        vec![policy_entry("invalid-discovery", &api_root)],
        None,
        Some(&["invalid-discovery".into()]),
    )
    .await
    .unwrap();
    let selected = ModelSelection {
        provider_id: "invalid-discovery".into(),
        model_id: "held-model".into(),
    };
    let owner = crate::client_inventory::ClientInventoryOwner::capture(
        &directory,
        &crate::plugin_runtime::RuntimePlugins::default(),
        &selected,
    )
    .unwrap();
    let mut observer = owner.catalog_subscription();
    let before = observer.current();
    assert!(before.discovery_pending());
    let query = ClientInventoryQueryV1 {
        kind: ClientInventoryKindV1::Providers,
        provider_id: None,
        offset: 0,
        limit: 25,
    };
    assert_eq!(
        owner.read(&query).unwrap()["records"][0]["discovery_pending"],
        true
    );
    owner.first_frame().unwrap();
    let after = tokio::time::timeout(Duration::from_secs(3), observer.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(!after.discovery_pending());
    assert!(after.discovery_error().is_some());
    assert!(
        before.discovery_pending(),
        "the old readonly value is immutable"
    );
    assert!(after.resolve_model(&invalid_model, None).is_err());
    let actual = owner.session_directory();
    assert!(actual.entry("invalid-discovery").unwrap().catalog.is_none());
    let page = owner.read(&query).unwrap();
    assert_eq!(page["inventory_digest_sha256"], after.inventory_digest());
    assert_eq!(page["records"][0]["discovery_pending"], false);
    assert!(page["records"][0]["discovery_error"].is_string());
    assert!(owner.first_frame().is_err());
    server.join().unwrap();
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn settle_publishes_the_catalogs_the_launch_deferred() {
    let routed = serde_json::json!({ "data": [{ "id": "routed-model" }] }).to_string();
    let (routed_root, routed_server) = spawn_json_server(routed);
    let deferred = serde_json::json!({ "data": [{ "id": "deferred-model" }] }).to_string();
    let (deferred_root, deferred_server) = spawn_json_server(deferred);

    let mut directory = ProviderDirectory::discover_entries_eagerly(
        vec![
            policy_entry("routed", &routed_root),
            policy_entry("later", &deferred_root),
        ],
        None,
        Some(&["routed".into()]),
    )
    .await
    .unwrap();
    assert!(
        directory.entry("later").unwrap().catalog.is_none(),
        "a deferred provider is not resolved before the picker asks for it"
    );
    // The picker needs every catalog, so it — and only it — starts and joins network work.
    directory.settle().await;
    routed_server.join().unwrap();
    deferred_server.join().unwrap();
    assert_eq!(
        directory
            .entry("later")
            .and_then(|entry| entry.catalog.as_ref())
            .map(|catalog| catalog.models[0].raw.id.as_str()),
        Some("deferred-model")
    );
    assert_eq!(
        directory.entry("routed").unwrap().catalog_provenance,
        CatalogProvenance::DynamicFresh,
        "settling publishes the selected route refresh as well as the other catalogs"
    );
    // Idempotent: the handle is joined once, and a second waiter reads what it published.
    let mut clone = directory.clone();
    clone.settle().await;
    directory.settle().await;
    assert!(clone.entry("later").unwrap().catalog.is_some());
}

#[tokio::test]
async fn every_uncached_provider_lookup_waits_only_at_first_use() {
    // Zero eager budget deliberately does not poll either endpoint before returning. Silent
    // listeners make that contract deterministic; a blocking fixture `join` here would stop
    // the current-thread Tokio runtime before its deferred refresh could even connect.
    let (api_root, routed_listener) = black_hole_api_root();
    let (black_hole, listener) = black_hole_api_root();
    let directory = ProviderDirectory::discover_entries_eagerly(
        vec![
            policy_entry("routed", &api_root),
            policy_entry("other", &black_hole),
        ],
        None,
        Some(&["routed".into()]),
    )
    .await
    .unwrap();

    assert!(
        directory.needs_settled_catalogs(Some("gpt-4o-mini"), "routed"),
        "zero-budget discovery leaves even the selected uncached catalog pending until use"
    );
    assert!(
        directory.needs_settled_catalogs(None, "routed"),
        "default selection cannot consume an uncached selected catalog before refresh"
    );
    assert!(
        directory.needs_settled_catalogs(Some("some-other-model"), "routed"),
        "an unqualified miss is resolved against every catalog and must settle first"
    );
    // A qualifier naming any deferred provider is still a read of that provider's catalog.
    assert!(
        directory.needs_settled_catalogs(Some("other:whatever"), "routed"),
        "a qualified id routed at a deferred provider must settle before its catalog is read"
    );
    assert!(
        directory.needs_settled_catalogs(Some("routed:whatever"), "routed"),
        "the selected route is also deferred when no local evidence resolved it"
    );
    // The regression this guards: `--resume` adopts the provider recorded in the rollout, so
    // the routed provider can be one the eager set never covered — with or without a model.
    // Routing on its unresolved catalog reported "no selectable discovered model" for a
    // provider that was merely still in flight.
    assert!(
        directory.needs_settled_catalogs(None, "other"),
        "a launch routed at a deferred provider must settle even with no model requested"
    );
    assert!(
        directory.needs_settled_catalogs(Some("gpt-4o-mini"), "other"),
        "a deferred routed provider must settle before its own catalog is consulted"
    );

    let fully_resolved = ProviderDirectory::discover_entries(Vec::new(), None)
        .await
        .unwrap();
    assert!(
        !fully_resolved.needs_settled_catalogs(Some("anything"), "routed"),
        "a directory with nothing outstanding never waits"
    );
    assert!(!fully_resolved.needs_settled_catalogs(None, "routed"));
    drop(routed_listener);
    drop(listener);
}

#[tokio::test]
async fn missing_credential_cannot_load_cached_inventory() {
    let path = test_cache_path("missing-key");
    let api_root = "http://127.0.0.1:9/v1";
    let source = catalogued_entry("missing-cache", api_root, "gpt-4o-mini");
    seed_cache(&path, &source);
    let target = offline_entry("missing-cache", AdapterKind::OpenAiCompatibleChat, true);

    let directory = ProviderDirectory::discover_entries(vec![target], Some(path.clone()))
        .await
        .unwrap();
    let cached = directory.entry("missing-cache").unwrap();
    assert!(!cached.catalog_stale);
    assert!(cached.catalog.is_none());
    assert_eq!(
        directory.health("missing-cache").availability,
        AccountAvailability::MissingCredential,
        "the credential early-exit proves no network result replaced account state"
    );
    let reason = directory.blocked_reason(cached).unwrap();
    assert!(reason.contains("missing credential"));
    assert!(!reason.contains("cached models"));
    assert!(
        directory
            .validate_selection(
                &ModelSelection {
                    provider_id: "missing-cache".into(),
                    model_id: "gpt-4o-mini".into(),
                },
                true,
            )
            .is_err()
    );
    remove_test_cache(&path);
}

#[tokio::test]
async fn d13_13_cache_identity_is_credential_scoped_across_accounts() {
    let path = test_cache_path("different-key");
    let api_root = closed_api_root();
    let source = catalogued_entry("different-cache", &api_root, "private-model");
    seed_cache(&path, &source);
    let target =
        policy_entry_with_credential("different-cache", &api_root, Some("replacement-key"));

    let directory = ProviderDirectory::discover_entries(vec![target], Some(path.clone()))
        .await
        .unwrap();
    let entry = directory.entry("different-cache").unwrap();
    assert!(!entry.catalog_stale);
    assert!(entry.catalog.is_none());
    assert!(entry.catalog_error.is_some());
    assert!(
        directory
            .resolve_model("private-model", Some("different-cache"))
            .is_err(),
        "inventory learned with one credential must be invisible after credential rotation"
    );
    remove_test_cache(&path);
}

#[test]
fn rotating_local_scope_key_invalidates_existing_cache() {
    let path = test_cache_path("rotated-local-key");
    let source = catalogued_entry(
        "scope-rotation",
        "https://gateway.example/v1",
        "private-model",
    );
    seed_cache(&path, &source);
    let cache = CatalogCache::load(&path);
    let original_key = test_scope_key(&path);
    assert!(cache.lookup(&source, &original_key).is_some());

    fs::remove_file(path.parent().unwrap().join(CATALOG_CACHE_SCOPE_KEY_FILE)).unwrap();
    let replacement_key = test_scope_key(&path);
    assert!(
        cache.lookup(&source, &replacement_key).is_none(),
        "an old HMAC must not survive local scope-key rotation"
    );
    remove_test_cache(&path);
}

#[tokio::test]
async fn expired_cache_cannot_skip_refresh_or_authorize_a_bare_selection() {
    let path = test_cache_path("expired");
    let api_root = closed_api_root();
    let source = catalogued_entry("expired-cache", &api_root, "gpt-4o-mini");
    seed_cache(&path, &source);
    let loaded = CatalogCache::load(&path);
    let mut entries = loaded.fixture_entries().to_vec();
    entries[0].fetched_at_unix_secs = current_unix_secs()
        .unwrap()
        .saturating_sub(CATALOG_CACHE_TTL_SECS + 1);
    let mut expired = CatalogCache::fixture_parts(CATALOG_CACHE_VERSION, entries);
    expired.save_atomic(&path).unwrap();
    let target = policy_entry("expired-cache", &api_root);

    let directory = ProviderDirectory::discover_entries(vec![target], Some(path.clone()))
        .await
        .unwrap();
    let entry = directory.entry("expired-cache").unwrap();
    assert!(!entry.catalog_stale);
    assert!(entry.catalog.is_none());
    assert!(entry.catalog_error.is_some());
    assert!(
        directory
            .validate_selection(
                &ModelSelection {
                    provider_id: "expired-cache".into(),
                    model_id: "gpt-4o-mini".into(),
                },
                true,
            )
            .is_ok(),
        "an explicit route is operator evidence, not cached-catalog authorization"
    );
    assert!(
        directory
            .resolve_model("gpt-4o-mini", Some("expired-cache"))
            .is_err(),
        "an expired cache must not authorize a bare picker selection"
    );
    remove_test_cache(&path);
}

#[test]
fn stale_display_evidence_does_not_make_bare_model_resolution_ambiguous() {
    let model_id = "gpt-4o-mini";
    let fresh = catalogued_entry("fresh", "https://fresh.example/v1", model_id);
    let mut stale = catalogued_entry("stale", "https://stale.example/v1", model_id);
    stale.catalog_stale = true;
    stale.catalog_provenance = CatalogProvenance::CachedFresh;
    let health = ProviderHealthStore::new(4);
    health.mark_ready("fresh");
    health.mark_ready("stale");
    let directory = ProviderDirectory {
        entries: Arc::new(vec![stale, fresh]),
        health,
        deferred: None,
        refresh_activity: ProviderRefreshActivity::default(),
    };

    assert_eq!(
        directory.resolve_model(model_id, Some("stale")).unwrap(),
        ModelSelection {
            provider_id: "fresh".into(),
            model_id: model_id.into(),
        }
    );
}

#[test]
fn route_digests_separate_dynamic_operator_static_and_cached_provenance() {
    let model_id = "gpt-4o-mini";
    let dynamic = catalogued_entry("same", "https://same.example/v1", model_id);
    let mut operator = dynamic.clone();
    operator.catalog_provenance = CatalogProvenance::OperatorManifest;
    let mut static_catalog = dynamic.clone();
    static_catalog.catalog_provenance = CatalogProvenance::StaticOfficial {
        version: "schema@test-v1".into(),
        source: "https://docs.example/schema".into(),
    };
    let mut cached_fresh = dynamic.clone();
    cached_fresh.catalog_provenance = CatalogProvenance::CachedFresh;
    let selection = ModelSelection {
        provider_id: "same".into(),
        model_id: model_id.into(),
    };
    let digest_for = |entry| {
        ProviderDirectory {
            entries: Arc::new(vec![entry]),
            health: ProviderHealthStore::new(1),
            deferred: None,
            refresh_activity: ProviderRefreshActivity::default(),
        }
        .selection_digests(&selection)
    };

    let digests = [
        digest_for(dynamic),
        digest_for(operator),
        digest_for(static_catalog),
        digest_for(cached_fresh),
    ];
    for left in 0..digests.len() {
        for right in left + 1..digests.len() {
            assert_ne!(digests[left], digests[right]);
        }
    }
}

#[test]
fn fatal_refresh_failures_keep_cached_names_informational_only() {
    for (availability, expected) in [
        (AccountAvailability::AuthenticationBlocked, "authentication"),
        (AccountAvailability::BillingBlocked, "balance"),
    ] {
        let mut entry =
            catalogued_entry("fatal-cache", "https://gateway.example/v1", "gpt-4o-mini");
        entry.catalog_stale = true;
        let health = ProviderHealthStore::new(4);
        let error = ProviderError::ApiResponse(iteron_provider::ApiResponseError {
            status: 403,
            body: "raw provider body".into(),
            body_truncated: false,
            retry_after: None,
            normalized: Box::new(iteron_provider::NormalizedFailure {
                adapter: AdapterKind::OpenAiCompatibleChat,
                error_profile: ErrorProfile::CustomConservative,
                code: Some("fatal".into()),
                public_message: "account unavailable",
                scope: iteron_provider::ErrorScope::Account,
                availability: iteron_provider::AvailabilityTransition::Account(availability),
                retry: iteron_provider::RetryDisposition::Never,
                request_id: None,
            }),
        });
        apply_catalog_failure(&mut entry, &health, &error);
        assert!(entry.catalog.is_some(), "cached names remain visible");
        let directory = ProviderDirectory {
            entries: Arc::new(vec![entry]),
            health,
            deferred: None,
            refresh_activity: ProviderRefreshActivity::default(),
        };
        assert!(
            directory
                .blocked_reason(&directory.entries()[0])
                .unwrap()
                .contains(expected)
        );
    }

    let mut entry = catalogued_entry("config-cache", "https://gateway.example/v1", "gpt-4o-mini");
    entry.catalog_stale = true;
    let health = ProviderHealthStore::new(4);
    apply_catalog_failure(
        &mut entry,
        &health,
        &ProviderError::Configuration("bad catalog strategy".into()),
    );
    let directory = ProviderDirectory {
        entries: Arc::new(vec![entry]),
        health,
        deferred: None,
        refresh_activity: ProviderRefreshActivity::default(),
    };
    assert!(
        directory
            .blocked_reason(&directory.entries()[0])
            .unwrap()
            .contains("configuration")
    );
}

#[test]
fn catalog_only_permission_failure_allows_only_explicit_inference_fallback() {
    let mut entry = catalogued_entry("list-denied", "https://gateway.example/v1", "cached-model");
    entry.catalog_stale = true;
    let health = ProviderHealthStore::new(4);
    let error = ProviderError::ApiResponse(iteron_provider::ApiResponseError {
        status: 403,
        body: "secret provider payload".into(),
        body_truncated: false,
        retry_after: None,
        normalized: Box::new(iteron_provider::NormalizedFailure {
            adapter: AdapterKind::OpenAiCompatibleChat,
            error_profile: ErrorProfile::CustomConservative,
            code: Some("permission_denied".into()),
            public_message: "provider permission is unavailable",
            scope: iteron_provider::ErrorScope::Account,
            availability: iteron_provider::AvailabilityTransition::Account(
                AccountAvailability::PermissionBlocked,
            ),
            retry: iteron_provider::RetryDisposition::Never,
            request_id: None,
        }),
    });
    apply_catalog_failure(&mut entry, &health, &error);
    assert_eq!(
        health.get("list-denied").availability,
        AccountAvailability::Unknown,
        "catalog permission is not inference permission evidence"
    );
    assert!(entry.catalog_fallback_explicit);
    let directory = ProviderDirectory {
        entries: Arc::new(vec![entry]),
        health,
        deferred: None,
        refresh_activity: ProviderRefreshActivity::default(),
    };
    assert!(
        directory
            .validate_selection(
                &ModelSelection {
                    provider_id: "list-denied".into(),
                    model_id: "operator-known-model".into(),
                },
                true,
            )
            .is_ok()
    );
    assert!(
        directory
            .resolve_model("cached-model", Some("list-denied"))
            .is_err(),
        "stale picker leaves remain informational and disabled"
    );
}

#[test]
fn catalog_then_authoritative_probe_has_deterministic_recovery_semantics() {
    let billing_error = || {
        ProviderError::ApiResponse(iteron_provider::ApiResponseError {
            status: 429,
            body: "private provider payload".into(),
            body_truncated: false,
            retry_after: None,
            normalized: Box::new(iteron_provider::NormalizedFailure {
                adapter: AdapterKind::OpenAiCompatibleChat,
                error_profile: ErrorProfile::DeepSeek,
                code: Some("insufficient_quota".into()),
                public_message: "provider billing or quota is unavailable",
                scope: iteron_provider::ErrorScope::Account,
                availability: iteron_provider::AvailabilityTransition::Account(
                    AccountAvailability::BillingBlocked,
                ),
                retry: iteron_provider::RetryDisposition::Never,
                request_id: Some("catalog-request".into()),
            }),
        })
    };
    let positive_balance = || AccountProbeResult {
        availability: AccountAvailability::Ready,
        balance: BalanceAvailability::Sufficient,
    };

    let mut catalog_then_probe = policy_entry("catalog-then-probe", "https://gateway.example/v1");
    let health = ProviderHealthStore::new(2);
    apply_catalog_result(&mut catalog_then_probe, &health, Err(billing_error()));
    assert_eq!(
        health.get(catalog_then_probe.id()).availability,
        AccountAvailability::BillingBlocked
    );
    apply_probe_result(
        &catalog_then_probe,
        &health,
        AccountProbe::DeepSeekBalance,
        Ok(positive_balance()),
    );
    assert_eq!(
        health.get(catalog_then_probe.id()),
        ProviderHealth {
            availability: AccountAvailability::Ready,
            balance: BalanceAvailability::Sufficient,
            last_error_code: None,
            last_request_id: None,
        },
        "the later documented positive-balance probe is authoritative recovery evidence"
    );

    let mut probe_then_catalog = policy_entry("probe-then-catalog", "https://gateway.example/v1");
    apply_probe_result(
        &probe_then_catalog,
        &health,
        AccountProbe::DeepSeekBalance,
        Ok(positive_balance()),
    );
    apply_catalog_result(&mut probe_then_catalog, &health, Err(billing_error()));
    assert_eq!(
        health.get(probe_then_catalog.id()).availability,
        AccountAvailability::BillingBlocked,
        "reversing observation order has different semantics, so concurrent completion cannot be relabelled after the fact"
    );
}

#[test]
fn catalog_transport_error_is_publicly_redacted() {
    let mut entry = policy_entry("safe-error", "https://gateway.example/v1");
    let health = ProviderHealthStore::new(1);
    apply_catalog_failure(
        &mut entry,
        &health,
        &ProviderError::Http(
            "request failed for https://gateway.example/models?pageToken=sk-secret".into(),
        ),
    );
    let visible = entry.catalog_error.unwrap();
    assert_eq!(visible, "provider transport failed");
    assert!(!visible.contains("sk-secret"));
}

#[test]
fn catalog_disabled_suppresses_the_account_probe_as_documented() {
    // `catalog = false` is documented as the opt-out from discovery traffic for one instance.
    // It gated only `GET /models`, so DeepSeek and Fireworks still paid an account round trip
    // on every single launch despite the operator having turned discovery off.
    let mut deepseek = policy_entry("deepseek", DEEPSEEK_API_ROOT);
    assert_eq!(
        account_probe_for(&deepseek),
        Some(AccountProbe::DeepSeekBalance)
    );
    deepseek.catalog_enabled = false;
    assert_eq!(account_probe_for(&deepseek), None);

    let fireworks = builtin_entries()
        .unwrap()
        .into_iter()
        .find(|entry| entry.id() == "fireworks")
        .unwrap();
    assert_eq!(
        account_probe_for(&fireworks),
        Some(AccountProbe::FireworksSuspendState)
    );
    let mut disabled = fireworks;
    disabled.catalog_enabled = false;
    assert_eq!(account_probe_for(&disabled), None);
}

#[test]
fn probe_cache_reuses_fresh_evidence_and_backs_a_failing_account_off_exponentially() {
    let policy = ProviderDiscoveryPolicy::owner();
    let path = test_cache_path("probe-decisions");
    let scope_key = test_scope_key(&path);
    let entry = policy_entry("deepseek", DEEPSEEK_API_ROOT);
    let identity =
        probe_identity(&entry, AccountProbe::DeepSeekBalance, &scope_key).expect("scoped");
    let now = 1_800_000_000_u64;

    // No record at all: probe, extending a zero-length failure run.
    let empty = ProbeCache::default();
    assert_eq!(
        empty.decide(&identity, now, policy),
        ProbeDecision::Run { failures: 0 }
    );

    let observe = |observed_at, outcome| {
        let mut cache = ProbeCache::default();
        cache.upsert(CachedProbe {
            provider_id: identity.0.clone(),
            api_root: identity.1.clone(),
            probe: identity.2.clone(),
            credential_scope: identity.3.clone(),
            observed_at_unix_secs: observed_at,
            outcome,
        });
        cache
    };
    let ready = CachedProbeOutcome::Observed {
        availability: CachedAvailability::Ready,
        balance: CachedBalance::Sufficient,
    };
    assert_eq!(
        observe(now - 1, ready).decide(&identity, now, policy),
        ProbeDecision::Reuse(AccountProbeResult {
            availability: AccountAvailability::Ready,
            balance: BalanceAvailability::Sufficient,
        }),
        "a fresh observation stands in for the request"
    );
    assert_eq!(
        observe(now - PROBE_CACHE_TTL_SECS, ready).decide(&identity, now, policy),
        ProbeDecision::Run { failures: 0 },
        "past the TTL the account is observed again"
    );
    // A record stamped in the future is a clock change, not evidence.
    assert_eq!(
        observe(now + 1, ready).decide(&identity, now, policy),
        ProbeDecision::Run { failures: 0 }
    );

    // The defect: a key rejected weeks ago cost a round trip on EVERY launch, because a failed
    // probe was never written back at all.
    let failed = |failures| CachedProbeOutcome::Failed {
        consecutive_failures: failures,
    };
    assert_eq!(
        observe(now - 1, failed(1)).decide(&identity, now, policy),
        ProbeDecision::Skip
    );
    assert_eq!(
        observe(now - PROBE_BACKOFF_BASE_SECS, failed(1)).decide(&identity, now, policy),
        ProbeDecision::Run { failures: 1 },
        "the run length is carried forward so the next wait doubles"
    );
    assert_eq!(probe_backoff_secs(policy, 0), 0);
    assert_eq!(probe_backoff_secs(policy, 1), PROBE_BACKOFF_BASE_SECS);
    assert_eq!(probe_backoff_secs(policy, 2), PROBE_BACKOFF_BASE_SECS * 2);
    assert_eq!(probe_backoff_secs(policy, u32::MAX), PROBE_BACKOFF_CAP_SECS);
    // Yesterday's failure, today's launch: still inside the capped window, still no request.
    assert_eq!(
        observe(now - 20 * 60 * 60, failed(24)).decide(&identity, now, policy),
        ProbeDecision::Skip
    );

    // A different credential, endpoint, or probe kind never inherits the verdict.
    let mut other = identity.clone();
    other.3 = format!("{}{}", CATALOG_CACHE_SCOPE_PREFIX, "ab".repeat(32));
    assert_eq!(
        observe(now - 1, failed(9)).decide(&other, now, policy),
        ProbeDecision::Run { failures: 0 }
    );
    remove_test_cache(&path);
}

#[test]
fn probe_cache_round_trips_atomically_and_rejects_corruption() {
    let path = test_cache_path("probe-round-trip");
    let probe_path = probe_cache_path_for(Some(&path)).unwrap();
    let scope_key = test_scope_key(&path);
    let entry = policy_entry("deepseek", DEEPSEEK_API_ROOT);
    let identity =
        probe_identity(&entry, AccountProbe::DeepSeekBalance, &scope_key).expect("scoped");

    let mut cache = ProbeCache::default();
    cache.upsert(CachedProbe {
        provider_id: identity.0.clone(),
        api_root: identity.1.clone(),
        probe: identity.2.clone(),
        credential_scope: identity.3.clone(),
        observed_at_unix_secs: 1_800_000_000,
        outcome: CachedProbeOutcome::Failed {
            consecutive_failures: 3,
        },
    });
    cache.save_atomic(&probe_path).unwrap();

    let text = fs::read_to_string(&probe_path).unwrap();
    assert!(
        !text.contains("test-key"),
        "credentials must never be cached"
    );
    assert!(text.contains(CATALOG_CACHE_SCOPE_PREFIX));
    let loaded = ProbeCache::load(&probe_path);
    assert_eq!(loaded.fixture_entries().len(), 1);
    assert_eq!(
        loaded.decide(&identity, 1_800_000_001, ProviderDiscoveryPolicy::owner(),),
        ProbeDecision::Skip
    );

    fs::write(&probe_path, br#"{"version":999,"entries":[]}"#).unwrap();
    assert!(ProbeCache::load(&probe_path).fixture_entries().is_empty());
    fs::write(&probe_path, b"{not-json").unwrap();
    assert!(ProbeCache::load(&probe_path).fixture_entries().is_empty());
    fs::write(&probe_path, vec![b' '; MAX_PROBE_CACHE_BYTES + 1]).unwrap();
    assert!(ProbeCache::load(&probe_path).fixture_entries().is_empty());
    // An unrecognized probe kind is not evidence about any probe this binary can run.
    let unknown = ProbeCache::fixture_parts(
        PROBE_CACHE_VERSION,
        vec![CachedProbe {
            provider_id: identity.0.clone(),
            api_root: identity.1.clone(),
            probe: "some-future-probe".into(),
            credential_scope: identity.3.clone(),
            observed_at_unix_secs: 1_800_000_000,
            outcome: CachedProbeOutcome::Failed {
                consecutive_failures: 1,
            },
        }],
    );
    assert!(!unknown.is_valid());
    remove_test_cache(&path);
}

#[test]
fn builtin_catalog_and_probe_strategies_are_provider_specific() {
    let entries = builtin_entries().unwrap();
    let deepseek = entries
        .iter()
        .find(|entry| entry.id() == "deepseek")
        .unwrap();
    let glm = entries.iter().find(|entry| entry.id() == "glm").unwrap();
    let minimax = entries
        .iter()
        .find(|entry| entry.id() == "minimax")
        .unwrap();
    let fireworks = entries
        .iter()
        .find(|entry| entry.id() == "fireworks")
        .unwrap();

    assert_eq!(
        account_probe_for(deepseek),
        Some(AccountProbe::DeepSeekBalance)
    );
    assert_eq!(minimax.instance.api_root().as_str(), MINIMAX_API_ROOT);
    assert!(matches!(
        fireworks.instance.catalog_strategy(),
        CatalogStrategy::FireworksControlPlane { api_root }
            if api_root.as_str() == "https://api.fireworks.ai/v1"
    ));
    assert_eq!(
        account_probe_for(fireworks),
        Some(AccountProbe::FireworksSuspendState)
    );

    assert!(matches!(
        glm.instance.catalog_strategy(),
        CatalogStrategy::Unsupported { reason }
            if reason.contains("no model-list endpoint")
    ));
    assert!(!glm.catalog_enabled, "GLM must never guess GET /models");
    let catalog = glm
        .catalog
        .as_ref()
        .expect("built-in GLM must expose its official static schema");
    assert_eq!(
        catalog.models.len(),
        glm.instance.static_metadata().glm_models().len()
    );
    assert!(catalog.models.iter().all(|model| {
        glm.instance
            .static_metadata()
            .glm_models()
            .contains(&model.raw.id)
            && model.compatibility == Compatibility::Compatible
            && model.selectability == Selectability::Selectable
    }));
    assert!(
        glm.catalog_error.is_none(),
        "the official static schema is not a catalog failure"
    );
}

#[test]
fn minimax_text_overlay_updates_flat_and_family_descriptors() {
    let entry = policy_entry("minimax", MINIMAX_API_ROOT);
    let unknown = descriptor(
        "MiniMax-M2.1",
        Compatibility::Unknown,
        Selectability::Disabled {
            reason: "coding-turn compatibility is unknown",
        },
    );
    let image = descriptor(
        "MiniMax-Image-01",
        Compatibility::Incompatible,
        Selectability::Disabled {
            reason: "model is not a coding-turn model",
        },
    );
    let mut catalog = snapshot("minimax", vec![unknown, image]);
    apply_provider_catalog_policy(&entry, &mut catalog);

    for models in [
        catalog.models.as_slice(),
        catalog.families[0].models.as_slice(),
    ] {
        assert_eq!(models[0].compatibility, Compatibility::Compatible);
        assert_eq!(models[0].selectability, Selectability::Selectable);
        assert_eq!(models[1].compatibility, Compatibility::Incompatible);
        assert!(matches!(
            models[1].selectability,
            Selectability::Disabled { .. }
        ));
    }
}

#[test]
fn openai_fine_tuned_text_id_remains_one_model_id_and_is_selectable() {
    let mut entry = policy_entry("openai", OPENAI_API_ROOT);
    let model_id = "ft:gpt-4o-mini-2024-07-18:org:project:suffix:id";
    let unknown = descriptor(
        model_id,
        Compatibility::Unknown,
        Selectability::Disabled {
            reason: "coding-turn compatibility is unknown",
        },
    );
    let mut catalog = snapshot("openai", vec![unknown]);
    apply_provider_catalog_policy(&entry, &mut catalog);
    assert_eq!(catalog.models[0].selectability, Selectability::Selectable);
    entry.catalog = Some(catalog);

    let health = ProviderHealthStore::new(4);
    health.mark_ready("openai");
    let directory = ProviderDirectory {
        entries: Arc::new(vec![entry]),
        health,
        deferred: None,
        refresh_activity: ProviderRefreshActivity::default(),
    };
    assert_eq!(
        directory.resolve_model(model_id, Some("openai")).unwrap(),
        ModelSelection {
            provider_id: "openai".into(),
            model_id: model_id.into(),
        },
        "the colon inside an OpenAI fine-tune id is not a provider separator"
    );
}

#[test]
fn fireworks_control_plane_metadata_is_not_weakened_by_name_heuristics() {
    let entry = policy_entry("fireworks", "https://api.fireworks.ai/inference/v1");
    let selectable = descriptor(
        "accounts/fireworks/models/qwen-good",
        Compatibility::Compatible,
        Selectability::Selectable,
    );
    let disabled = descriptor(
        "accounts/fireworks/models/qwen-no-tools",
        Compatibility::Incompatible,
        Selectability::Disabled {
            reason: "Fireworks model does not advertise tool calling",
        },
    );
    let mut catalog = snapshot("fireworks", vec![selectable, disabled]);
    let before = catalog.clone();
    apply_provider_catalog_policy(&entry, &mut catalog);
    assert_eq!(catalog, before);
}

#[test]
fn fireworks_model_image_evidence_reaches_runtime_provider() {
    let mut entry = policy_entry("fireworks", "https://api.fireworks.ai/inference/v1");
    let mut minimax = descriptor(
        "accounts/fireworks/models/minimax-m3",
        Compatibility::Compatible,
        Selectability::Selectable,
    );
    minimax.raw.supports_image_input = Some(true);
    entry.catalog = Some(snapshot("fireworks", vec![minimax]));
    entry.catalog_provenance = CatalogProvenance::DynamicFresh;
    let health = ProviderHealthStore::new(4);
    health.mark_ready("fireworks");
    let directory = ProviderDirectory {
        entries: Arc::new(vec![entry]),
        health,
        deferred: None,
        refresh_activity: ProviderRefreshActivity::default(),
    };
    let selection = ModelSelection {
        provider_id: "fireworks".into(),
        model_id: "accounts/fireworks/models/minimax-m3".into(),
    };

    let capabilities = directory.selection_capabilities(&selection);
    assert_eq!(capabilities.image_input, Some(true));
    assert_eq!(
        capabilities.image_input_source.as_deref(),
        Some(FIREWORKS_IMAGE_CAPABILITY_SOURCE)
    );
    assert!(directory.build(&selection).unwrap().supports_image_input());
}

#[tokio::test]
async fn glm_static_schema_is_account_neutral_and_uses_documented_default() {
    let directory =
        ProviderDirectory::discover_entries(vec![glm_static_entry(Some("test-key".into()))], None)
            .await
            .unwrap();
    assert_eq!(
        directory.health("glm").availability,
        AccountAvailability::Unknown,
        "a schema enum is not credential entitlement evidence"
    );
    assert_eq!(
        directory.resolve_model("glm:glm-5.2", None).unwrap(),
        ModelSelection {
            provider_id: "glm".into(),
            model_id: "glm-5.2".into(),
        }
    );
    assert_eq!(
        directory.default_selection("glm").unwrap().model_id,
        "glm-5.2"
    );
    let capabilities = directory.selection_capabilities(&ModelSelection {
        provider_id: "glm".into(),
        model_id: "glm-5.2".into(),
    });
    assert_eq!(capabilities.context_window_tokens, Some(1_000_000));
    assert_eq!(capabilities.max_output_tokens, Some(128_000));
    assert_eq!(capabilities.tool_calling, Some(true));
    assert_eq!(capabilities.semantic_effort, Some(true));
    assert!(
        capabilities
            .version
            .as_deref()
            .is_some_and(|version| version.starts_with("glm-5.2-model-page@2026-07-15+sha256:"))
    );
    assert_eq!(
        capabilities.source.as_deref(),
        Some("https://docs.bigmodel.cn/cn/guide/models/text/glm-5.2")
    );
    assert_eq!(
        directory.selection_capabilities(&ModelSelection {
            provider_id: "glm".into(),
            model_id: "glm-5.1".into(),
        }),
        ModelCapabilities::unknown(),
        "a family neighbour never inherits GLM-5.2 limits"
    );
    assert!(
        directory
            .resolve_model("glm:glm-undocumented", None)
            .unwrap_err()
            .contains("not in")
    );
    assert!(
        directory
            .status_label(directory.entry("glm").unwrap())
            .contains("official static schema · account entitlement unknown")
    );
}

#[test]
fn built_in_openai_default_prefers_codex_v0156_admitted_model_without_overriding_explicit() {
    let mut entry = builtin_entries()
        .unwrap()
        .into_iter()
        .find(|entry| entry.id() == "openai")
        .unwrap();
    let mut catalog = snapshot(
        "openai",
        vec![
            descriptor(
                "gpt-4o",
                Compatibility::Compatible,
                Selectability::Selectable,
            ),
            descriptor(
                "gpt-5.6-sol",
                Compatibility::Compatible,
                Selectability::Selectable,
            ),
            descriptor(
                "gpt-6-astra",
                Compatibility::Compatible,
                Selectability::Selectable,
            ),
        ],
    );
    catalog.adapter = AdapterKind::OpenAiResponses;
    entry.catalog = Some(catalog);
    entry.catalog_provenance = CatalogProvenance::DynamicFresh;
    let health = ProviderHealthStore::new(4);
    health.mark_ready("openai");
    let directory = ProviderDirectory {
        entries: Arc::new(vec![entry]),
        health,
        deferred: None,
        refresh_activity: ProviderRefreshActivity::default(),
    };

    assert_eq!(
        directory.default_selection("openai").unwrap().model_id,
        "gpt-6-astra"
    );
    assert_eq!(
        directory
            .resolve_model("openai:gpt-4o", None)
            .unwrap()
            .model_id,
        "gpt-4o",
        "an explicit model remains authoritative"
    );

    let mut without_astra = (*directory.entries).clone();
    without_astra[0]
        .catalog
        .as_mut()
        .unwrap()
        .models
        .retain(|model| model.raw.id != "gpt-6-astra");
    let directory_without_astra = ProviderDirectory {
        entries: Arc::new(without_astra),
        health: directory.health.clone(),
        deferred: None,
        refresh_activity: ProviderRefreshActivity::default(),
    };
    assert_eq!(
        directory_without_astra
            .default_selection("openai")
            .unwrap()
            .model_id,
        "gpt-5.6-sol",
        "the preferred model must be present in this credential's admitted catalog"
    );
}

#[tokio::test]
async fn refreshed_static_metadata_updates_catalog_capability_adapter_and_run_notice() {
    let now = current_unix_secs().unwrap();
    let captured = now.saturating_sub(42 * 24 * 60 * 60);
    let mut document: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../provider/static-provider-metadata-v1.json"
    ))
    .unwrap();
    document["bundle_revision"] = serde_json::json!("operator-refresh@test-v2");
    document["glm_standard_chat"]["version"] =
        serde_json::json!("glm-chat-completions-schema@test-v2");
    document["glm_standard_chat"]["captured_at_unix_secs"] = serde_json::json!(captured);
    document["glm_standard_chat"]["default_model"] = serde_json::json!("glm-5.1");
    document["glm_standard_chat"]["capabilities"]["glm-5.1"] = serde_json::json!({
        "version": "glm-5.1-model-page@test-v2",
        "source": "https://docs.bigmodel.cn/operator-refresh-test",
        "captured_at_unix_secs": captured,
        "context_window_tokens": 131072,
        "max_output_tokens": 8192,
        "tool_calling": true,
        "semantic_effort": true
    });
    StaticProviderMetadata::stamp_content_versions(&mut document).unwrap();
    let metadata = Arc::new(
        StaticProviderMetadata::from_slice(&serde_json::to_vec(&document).unwrap()).unwrap(),
    );
    let directory = ProviderDirectory::discover_entries(
        vec![glm_static_entry_with_metadata(
            Some("test-key".into()),
            metadata,
        )],
        None,
    )
    .await
    .unwrap();
    let selection = directory.default_selection("glm").unwrap();
    assert_eq!(selection.model_id, "glm-5.1");
    let capabilities = directory.selection_capabilities(&selection);
    assert_eq!(capabilities.context_window_tokens, Some(131_072));
    assert_eq!(capabilities.max_output_tokens, Some(8_192));
    assert!(
        capabilities
            .version
            .as_deref()
            .is_some_and(|version| version.starts_with("glm-5.1-model-page@test-v2+sha256:"))
    );

    let provider = directory.build(&selection).unwrap();
    let request = TurnRequest {
        model: selection.model_id,
        system: "stable prefix".into(),
        messages: Vec::new(),
        input_images: Vec::new(),
        tools: Vec::new().into(),
        max_tokens: 1_024,
        cache_system: true,
        thinking_budget: 4_096,
        reasoning_effort: iteron_protocol::ReasoningEffort::Medium,
        controls: Default::default(),
    };
    assert!(matches!(
        provider.effort_application(&request),
        iteron_provider::EffortApplication::Mapped { .. }
    ));
    let notice = provider.run_notice(&request).unwrap();
    assert_eq!(notice.code, "static_metadata");
    assert!(notice.message.contains("42 days old (stale)"));
    assert!(notice.message.contains("provider revision changed"));
    assert_eq!(
        provider.run_notice(&request),
        Some(notice),
        "the proposal remains repeatable until the kernel durably commits it"
    );
}

/// I-05 — `default_selection` returns `None` for four unrelated states, and the composition
/// root collapsed all four into `provider ... has no selectable discovered model`. Each state
/// must produce its own message, and a missing credential must name the variable to set.
#[tokio::test]
async fn i05_each_unresolvable_state_produces_a_distinguishable_message() {
    // No key: the reason the directory already computed names the exact variable, and the
    // message points at the wizard instead of at nothing.
    let directory = ProviderDirectory::discover_entries(vec![glm_static_entry(None)], None)
        .await
        .unwrap();
    assert!(directory.default_selection("glm").is_none());
    let missing = directory.resolution_error("glm");
    assert!(missing.contains("GLM_API_KEY"), "{missing}");
    assert!(missing.contains("iteron setup --byok glm"), "{missing}");
    assert!(
        !missing.contains("has no selectable discovered model"),
        "the unactionable line must not survive: {missing}"
    );

    // A rejected key is a different state and says so, naming the credential to replace.
    let directory =
        ProviderDirectory::discover_entries(vec![glm_static_entry(Some("wrong".into()))], None)
            .await
            .unwrap();
    directory.health.update_from_error(
        "glm",
        &ProviderError::ApiResponse(iteron_provider::ApiResponseError {
            status: 401,
            body: String::new(),
            body_truncated: false,
            retry_after: None,
            normalized: Box::new(iteron_provider::NormalizedFailure {
                adapter: AdapterKind::OpenAiCompatibleChat,
                error_profile: ErrorProfile::Glm,
                code: Some("invalid_api_key".into()),
                public_message: "authentication failed",
                scope: iteron_provider::ErrorScope::Account,
                availability: iteron_provider::AvailabilityTransition::Account(
                    AccountAvailability::AuthenticationBlocked,
                ),
                retry: iteron_provider::RetryDisposition::Never,
                request_id: None,
            }),
        }),
    );
    let rejected = directory.resolution_error("glm");
    assert!(rejected.contains("authentication failed"), "{rejected}");
    assert!(rejected.contains("rejected"), "{rejected}");
    assert_ne!(rejected, missing);

    // An unreachable provider — credentialed, so this is NOT the missing-credential state —
    // carries its discovery failure and its endpoint.
    let mut offline = offline_entry("gw", AdapterKind::OpenAiCompatibleChat, true);
    offline.instance = offline
        .instance
        .with_credential_source(CredentialSource::env("GW_KEY", Some("present".into())));
    let unreachable = ProviderDirectory::discover_entries(vec![offline], None)
        .await
        .unwrap();
    let message = unreachable.resolution_error("gw");
    assert!(message.contains("127.0.0.1:9"), "{message}");
    assert!(
        !message.contains("missing credential"),
        "an unreachable provider is not a missing credential: {message}"
    );
    assert_ne!(message, missing);
    assert_ne!(message, rejected);

    // A stale cached catalog is display evidence only, and keeps its own line.
    let mut stale = catalogued_entry("stale", "https://stale.example/v1", "m-1");
    stale.catalog_stale = true;
    let stale = ProviderDirectory::discover_entries(vec![stale], None)
        .await
        .unwrap();
    let message_stale = stale.resolution_error("stale");
    assert!(
        message_stale.contains("stale cached catalog"),
        "{message_stale}"
    );
    assert_ne!(message_stale, message);

    // A provider that is not configured at all lists what IS configured.
    let unknown = unreachable.resolution_error("nope");
    assert!(unknown.contains("not configured"), "{unknown}");
    assert!(unknown.contains("gw"), "{unknown}");
}

/// A credential file inside the workspace is reachable by `read_file`, `bash`, a child agent
/// and a hook. The composition root refuses that route instead of trusting confinement it
/// does not own; a file outside the workspace is not flagged.
#[tokio::test]
async fn i22_a_credential_file_inside_the_workspace_is_detected() {
    let workspace = std::env::temp_dir().join(format!(
        "core-credential-workspace-{}-{}",
        std::process::id(),
        CACHE_TEST_ID.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&workspace).unwrap();
    let inside = workspace.join("token");
    std::fs::write(&inside, "t\n").unwrap();

    let mut config = declaring_config("gw", "https://gw.example/v1", None, BTreeMap::new());
    config.key_env = None;
    config.credential = Some(ProviderCredential::File {
        path: inside.display().to_string(),
    });
    config.catalog = false;
    config.models = vec!["m-1".into()];
    let directory =
        ProviderDirectory::discover_entries(vec![entry_from_config(&config).unwrap()], None)
            .await
            .unwrap();
    assert_eq!(
        directory.credential_files_inside(&workspace),
        vec![inside.clone()],
        "a credential inside the workspace must be visible to the composition root"
    );
    assert!(
        directory
            .credential_files_inside(std::path::Path::new("/nonexistent-elsewhere"))
            .is_empty()
    );
    // Only names leave the directory, never values.
    assert!(directory.credential_env_names().is_empty());
    assert_eq!(directory.credential_file_paths(), vec![inside.clone()]);
    let _ = std::fs::remove_dir_all(&workspace);
}

#[tokio::test]
async fn glm_static_schema_without_key_is_visible_but_every_leaf_is_disabled() {
    let directory = ProviderDirectory::discover_entries(vec![glm_static_entry(None)], None)
        .await
        .unwrap();
    let entry = directory.entry("glm").unwrap();
    assert_eq!(
        directory.health("glm").availability,
        AccountAvailability::MissingCredential
    );
    assert!(
        directory
            .blocked_reason(entry)
            .unwrap()
            .contains("missing credential")
    );
    assert!(directory.default_selection("glm").is_none());
    for model in &entry.catalog.as_ref().unwrap().models {
        assert!(
            directory
                .resolve_model(&format!("glm:{}", model.raw.id), None)
                .unwrap_err()
                .contains("missing credential")
        );
    }
}

fn declaring_config(
    id: &str,
    api_root: &str,
    error_profile: Option<&str>,
    capabilities: BTreeMap<String, crate::config::ProviderModelCapabilities>,
) -> ProviderConfig {
    ProviderConfig {
        id: id.into(),
        display_name: None,
        adapter: "openai_chat".into(),
        error_profile: error_profile.map(Into::into),
        api_root: api_root.into(),
        key_env: Some("GATEWAY_KEY".into()),
        credential: None,
        enabled: true,
        // Discovery off keeps this offline and makes the declared manifest the inventory.
        catalog: false,
        models: vec!["k3".into(), "k3-256k".into()],
        model_capabilities: capabilities,
    }
}

fn declared_window(
    model_id: &str,
    window: u64,
) -> BTreeMap<String, crate::config::ProviderModelCapabilities> {
    BTreeMap::from([(
        model_id.to_owned(),
        crate::config::ProviderModelCapabilities {
            context_window_tokens: Some(window),
            image_input: None,
            routing_objectives: None,
        },
    )])
}

fn declared_images(
    model_id: &str,
    supported: bool,
) -> BTreeMap<String, crate::config::ProviderModelCapabilities> {
    BTreeMap::from([(
        model_id.to_owned(),
        crate::config::ProviderModelCapabilities {
            context_window_tokens: None,
            image_input: Some(supported),
            routing_objectives: None,
        },
    )])
}

#[tokio::test]
async fn operator_can_declare_images_for_one_exact_custom_route_model() {
    let config = declaring_config(
        "gateway",
        "https://gateway.example/v1",
        None,
        declared_images("k3", true),
    );
    let directory =
        ProviderDirectory::discover_entries(vec![entry_from_config(&config).unwrap()], None)
            .await
            .unwrap();
    let supported = ModelSelection {
        provider_id: "gateway".into(),
        model_id: "k3".into(),
    };
    assert_eq!(
        directory.selection_capabilities(&supported).image_input,
        Some(true)
    );
    assert_eq!(
        directory
            .selection_capabilities(&ModelSelection {
                provider_id: "gateway".into(),
                model_id: "k3-256k".into(),
            })
            .image_input,
        None
    );
}

#[tokio::test]
async fn operator_declared_window_is_reported_with_operator_provenance() {
    let config = declaring_config(
        "kimi",
        "https://gateway.example/v1",
        None,
        declared_window("k3", 1_048_576),
    );
    let directory =
        ProviderDirectory::discover_entries(vec![entry_from_config(&config).unwrap()], None)
            .await
            .unwrap();

    let declared = directory.selection_capabilities(&ModelSelection {
        provider_id: "kimi".into(),
        model_id: "k3".into(),
    });
    assert_eq!(declared.context_window_tokens, Some(1_048_576));
    // Only the arithmetic bound is declarable. A hand-written number must not be able to
    // switch on a request feature or raise the output reservation.
    assert_eq!(declared.max_output_tokens, None);
    assert_eq!(declared.tool_calling, None);
    assert_eq!(declared.semantic_effort, None);
    // The provenance says "operator wrote this", not a version/source that would read like
    // captured vendor evidence.
    assert_eq!(
        declared.version.as_deref(),
        Some(OPERATOR_DECLARED_CAPABILITY_VERSION)
    );
    assert_eq!(
        declared.source.as_deref(),
        Some(OPERATOR_DECLARED_CAPABILITY_SOURCE)
    );

    // A declaration is per model id; a sibling in the same manifest inherits nothing.
    assert_eq!(
        directory.selection_capabilities(&ModelSelection {
            provider_id: "kimi".into(),
            model_id: "k3-256k".into(),
        }),
        ModelCapabilities::unknown(),
        "an undeclared sibling never inherits the declared window"
    );

    // Trusting a declared number is a different route than not trusting one, so the capability
    // digest must move. A rate card bound to the undeclared digest stops matching, by design.
    let undeclared = declaring_config("kimi", "https://gateway.example/v1", None, BTreeMap::new());
    let plain =
        ProviderDirectory::discover_entries(vec![entry_from_config(&undeclared).unwrap()], None)
            .await
            .unwrap();
    let selection = ModelSelection {
        provider_id: "kimi".into(),
        model_id: "k3".into(),
    };
    assert_eq!(
        plain.selection_capabilities(&selection),
        ModelCapabilities::unknown()
    );
    assert_ne!(
        directory.selection_digests(&selection).1,
        plain.selection_digests(&selection).1,
        "a declared window must change the capability digest"
    );
}

#[tokio::test]
async fn a_bundled_non_glm_route_reports_a_real_context_window() {
    // Before I-30 the capability gate additionally required the GLM adapter and error profile,
    // so every other provider resolved to unknown: the over-window preflight (which is gated on
    // `model_context_window`) never ran, and the statusline fell back to bytes-used.
    let config = ProviderConfig {
        id: "anthropic".into(),
        display_name: Some("Anthropic".into()),
        adapter: "anthropic_messages".into(),
        error_profile: Some("anthropic".into()),
        api_root: "https://api.anthropic.com/v1".into(),
        key_env: Some("ITERON_TEST_ABSENT_ANTHROPIC_KEY".into()),
        credential: None,
        enabled: true,
        catalog: false,
        models: vec!["claude-opus-4-7".into()],
        model_capabilities: BTreeMap::new(),
    };
    let directory =
        ProviderDirectory::discover_entries(vec![entry_from_config(&config).unwrap()], None)
            .await
            .unwrap();

    let selection = ModelSelection {
        provider_id: "anthropic".into(),
        model_id: "claude-opus-4-7".into(),
    };
    let capabilities = directory.selection_capabilities(&selection);
    assert_eq!(capabilities.context_window_tokens, Some(1_000_000));
    assert_eq!(capabilities.max_output_tokens, Some(128_000));
    assert!(
        capabilities
            .version
            .as_deref()
            .is_some_and(|version| version.starts_with("anthropic-model-overview@")),
        "the provenance is the captured vendor snapshot"
    );
    // The window is what the preflight and the percent-remaining statusline read.
    assert_ne!(capabilities, ModelCapabilities::unknown());

    // A wire-compatible gateway at another API root still inherits nothing.
    let mut lookalike = config.clone();
    lookalike.id = "anthropic-lookalike".into();
    lookalike.api_root = "https://gateway.example/v1".into();
    let plain =
        ProviderDirectory::discover_entries(vec![entry_from_config(&lookalike).unwrap()], None)
            .await
            .unwrap();
    assert_eq!(
        plain.selection_capabilities(&ModelSelection {
            provider_id: "anthropic-lookalike".into(),
            model_id: "claude-opus-4-7".into(),
        }),
        ModelCapabilities::unknown()
    );
}

#[test]
fn a_malformed_metadata_override_warns_and_falls_back_unless_strict() {
    let dir = std::env::temp_dir().join(format!(
        "iteron-provider-metadata-override-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("provider-metadata.json");
    std::fs::write(&path, b"{ not json").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    // One bad byte used to propagate out of discovery and take the whole run down (I-48).
    let (metadata, warning) = resolve_static_provider_metadata(Some(&path), false)
        .expect("a malformed override no longer prevents startup");
    assert_eq!(
        metadata.bundle_revision(),
        StaticProviderMetadata::embedded().bundle_revision()
    );
    let warning = warning.expect("the fallback is announced, never silent");
    assert!(
        warning.contains(&path.display().to_string()),
        "the warning names the file: {warning}"
    );
    assert!(
        warning.contains("schema-v1 JSON"),
        "the warning names the parse error: {warning}"
    );

    // The explicit strict flag restores fail-closed loading.
    assert!(resolve_static_provider_metadata(Some(&path), true).is_err());

    // An absent override is not an error, and a missing home selects the embedded document.
    std::fs::remove_file(&path).unwrap();
    assert_eq!(
        resolve_static_provider_metadata(Some(&path), true)
            .unwrap()
            .1,
        None
    );
    assert_eq!(
        resolve_static_provider_metadata(None, true).unwrap().1,
        None
    );
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn official_snapshot_outranks_an_operator_declaration_on_the_same_route() {
    let glm_root = StaticProviderMetadata::embedded().glm_api_root().to_owned();
    let mut config = declaring_config(
        "glm-lookalike",
        &glm_root,
        Some("glm"),
        declared_window("glm-5.2", 12_345),
    );
    config.models = vec!["glm-5.2".into()];
    let directory =
        ProviderDirectory::discover_entries(vec![entry_from_config(&config).unwrap()], None)
            .await
            .unwrap();

    let capabilities = directory.selection_capabilities(&ModelSelection {
        provider_id: "glm-lookalike".into(),
        model_id: "glm-5.2".into(),
    });
    assert_eq!(
        capabilities.context_window_tokens,
        Some(1_000_000),
        "the captured vendor snapshot wins over a hand-written number"
    );
    assert_eq!(capabilities.max_output_tokens, Some(128_000));
    assert!(
        capabilities
            .version
            .as_deref()
            .is_some_and(|version| version.starts_with("glm-5.2-model-page@")),
        "provenance must stay the vendor snapshot, not the declaration"
    );
}

#[test]
fn operator_manifest_becomes_a_sorted_selectable_manual_family() {
    let config = ProviderConfig {
        id: "gateway".into(),
        display_name: Some("Operator gateway".into()),
        adapter: "openai_chat".into(),
        error_profile: None,
        api_root: "https://gateway.example/v1".into(),
        key_env: Some("GATEWAY_KEY".into()),
        credential: None,
        enabled: true,
        catalog: false,
        models: vec!["vendor/model-b".into(), "vendor/model-a".into()],
        model_capabilities: BTreeMap::new(),
    };
    let entry = entry_from_config(&config).unwrap();
    let catalog = entry.catalog.as_ref().unwrap();
    assert_eq!(catalog.families.len(), 1);
    assert_eq!(catalog.families[0].id, "manual");
    assert_eq!(
        catalog.families[0].display_name,
        "Manual / operator declared"
    );
    assert_eq!(
        catalog
            .models
            .iter()
            .map(|model| model.raw.id.as_str())
            .collect::<Vec<_>>(),
        ["vendor/model-a", "vendor/model-b"]
    );
    assert!(catalog.models.iter().all(|model| {
        model.compatibility == Compatibility::Compatible
            && model.selectability == Selectability::Selectable
    }));

    let health = ProviderHealthStore::new(4);
    health.mark_ready("gateway");
    let directory = ProviderDirectory {
        entries: Arc::new(vec![entry]),
        health,
        deferred: None,
        refresh_activity: ProviderRefreshActivity::default(),
    };
    assert_eq!(
        directory
            .resolve_model("gateway:vendor/model-a", None)
            .unwrap()
            .model_id,
        "vendor/model-a"
    );
    assert!(
        directory
            .resolve_model("gateway:undeclared", None)
            .unwrap_err()
            .contains("not in")
    );
    assert!(
        directory
            .status_label(directory.entry("gateway").unwrap())
            .contains("manual catalog ready")
    );
}

#[test]
fn trusted_config_can_select_an_explicit_error_profile() {
    let mut config = ProviderConfig {
        id: "gateway".into(),
        display_name: None,
        adapter: "openai_chat".into(),
        error_profile: Some("deepseek".into()),
        api_root: "https://gateway.example/v1".into(),
        key_env: Some("GATEWAY_KEY".into()),
        credential: None,
        enabled: true,
        catalog: false,
        models: Vec::new(),
        model_capabilities: BTreeMap::new(),
    };
    assert_eq!(
        entry_from_config(&config).unwrap().instance.error_profile(),
        ErrorProfile::DeepSeek
    );

    config.error_profile = None;
    assert_eq!(
        entry_from_config(&config).unwrap().instance.error_profile(),
        ErrorProfile::CustomConservative,
        "an unknown root without an operator declaration remains conservative"
    );
    config.error_profile = Some("guess".into());
    assert!(entry_from_config(&config).is_err());
}

#[test]
fn known_unavailable_model_is_rejected_and_skipped_as_default() {
    let mut entry = offline_entry("gateway", AdapterKind::OpenAiCompatibleChat, true);
    entry.catalog = Some(snapshot(
        "gateway",
        vec![
            descriptor(
                "model-a",
                Compatibility::Compatible,
                Selectability::Selectable,
            ),
            descriptor(
                "model-b",
                Compatibility::Compatible,
                Selectability::Selectable,
            ),
        ],
    ));
    let health = ProviderHealthStore::new(4);
    health.mark_ready("gateway");
    health.update_from_turn_error(
        "gateway",
        "model-a",
        &ProviderError::ApiResponse(iteron_provider::ApiResponseError {
            status: 404,
            body: String::new(),
            body_truncated: false,
            retry_after: None,
            normalized: Box::new(iteron_provider::NormalizedFailure {
                adapter: AdapterKind::OpenAiCompatibleChat,
                error_profile: iteron_provider::ErrorProfile::CustomConservative,
                code: Some("model_not_found".into()),
                public_message: "model unavailable",
                scope: iteron_provider::ErrorScope::Model,
                availability: iteron_provider::AvailabilityTransition::ModelUnavailable,
                retry: iteron_provider::RetryDisposition::Never,
                request_id: None,
            }),
        }),
    );
    let directory = ProviderDirectory {
        entries: Arc::new(vec![entry]),
        health,
        deferred: None,
        refresh_activity: ProviderRefreshActivity::default(),
    };

    assert!(
        directory
            .validate_selection(
                &ModelSelection {
                    provider_id: "gateway".into(),
                    model_id: "model-a".into(),
                },
                true,
            )
            .unwrap_err()
            .contains("known unavailable")
    );
    assert_eq!(
        directory.default_selection("gateway").unwrap().model_id,
        "model-b"
    );
}

#[test]
fn explicit_retry_clears_only_the_model_leaf_and_never_an_account_gate() {
    let entry = catalogued_entry("retry-gateway", "https://gateway.example/v1", "model-a");
    let health = ProviderHealthStore::new(4);
    health.mark_ready("retry-gateway");
    let model_failure = ProviderError::ApiResponse(iteron_provider::ApiResponseError {
        status: 404,
        body: String::new(),
        body_truncated: false,
        retry_after: None,
        normalized: Box::new(iteron_provider::NormalizedFailure {
            adapter: AdapterKind::OpenAiCompatibleChat,
            error_profile: iteron_provider::ErrorProfile::CustomConservative,
            code: Some("model_not_found".into()),
            public_message: "model unavailable",
            scope: iteron_provider::ErrorScope::Model,
            availability: iteron_provider::AvailabilityTransition::ModelUnavailable,
            retry: iteron_provider::RetryDisposition::Never,
            request_id: None,
        }),
    });
    health.update_from_turn_error("retry-gateway", "model-a", &model_failure);
    let directory = ProviderDirectory {
        entries: Arc::new(vec![entry]),
        health: health.clone(),
        deferred: None,
        refresh_activity: ProviderRefreshActivity::default(),
    };
    let selection = ModelSelection {
        provider_id: "retry-gateway".into(),
        model_id: "model-a".into(),
    };

    assert!(directory.validate_selection(&selection, true).is_err());
    assert_eq!(
        directory.clear_model_unavailable_for_retry(&selection),
        Ok(true)
    );
    assert!(directory.validate_selection(&selection, true).is_ok());
    assert_eq!(
        directory.clear_model_unavailable_for_retry(&selection),
        Ok(false),
        "retry admission is explicit and one-shot"
    );

    health.update_from_turn_error("retry-gateway", "model-a", &model_failure);
    health.update_from_error(
        "retry-gateway",
        &ProviderError::ApiResponse(iteron_provider::ApiResponseError {
            status: 429,
            body: String::new(),
            body_truncated: false,
            retry_after: None,
            normalized: Box::new(iteron_provider::NormalizedFailure {
                adapter: AdapterKind::OpenAiCompatibleChat,
                error_profile: iteron_provider::ErrorProfile::OpenAi,
                code: Some("insufficient_quota".into()),
                public_message: "provider billing or quota is unavailable",
                scope: iteron_provider::ErrorScope::Account,
                availability: iteron_provider::AvailabilityTransition::Account(
                    AccountAvailability::BillingBlocked,
                ),
                retry: iteron_provider::RetryDisposition::Never,
                request_id: None,
            }),
        }),
    );
    assert!(
        directory
            .clear_model_unavailable_for_retry(&selection)
            .is_err()
    );
    assert!(health.is_model_unavailable("retry-gateway", "model-a"));
    assert_eq!(
        health.blocked_account("retry-gateway"),
        Some(AccountAvailability::BillingBlocked)
    );
}

#[test]
fn missing_credential_is_grey_and_unknown_balance_is_not() {
    let missing = offline_entry("missing", AdapterKind::OpenAiCompatibleChat, true);
    let health = ProviderHealthStore::new(4);
    health.mark_missing_credential(missing.id());
    let directory = ProviderDirectory {
        entries: Arc::new(vec![missing.clone()]),
        health: health.clone(),
        deferred: None,
        refresh_activity: ProviderRefreshActivity::default(),
    };
    assert!(
        directory
            .blocked_reason(&missing)
            .unwrap()
            .contains("missing")
    );

    let health = ProviderHealthStore::new(4);
    health.mark_ready(missing.id());
    let directory = ProviderDirectory {
        entries: Arc::new(vec![missing.clone()]),
        health,
        deferred: None,
        refresh_activity: ProviderRefreshActivity::default(),
    };
    assert_eq!(
        directory.health(missing.id()).balance,
        BalanceAvailability::Unknown
    );
    assert!(directory.blocked_reason(&missing).is_none());
    assert!(directory.status_label(&missing).contains("balance unknown"));
}

#[test]
fn explicit_model_is_only_allowed_for_catalog_disabled_gateway() {
    let gateway = offline_entry("gateway", AdapterKind::OpenAiCompatibleChat, false);
    let health = ProviderHealthStore::new(4);
    health.mark_ready(gateway.id());
    let directory = ProviderDirectory {
        entries: Arc::new(vec![gateway]),
        health,
        deferred: None,
        refresh_activity: ProviderRefreshActivity::default(),
    };
    assert_eq!(
        directory
            .resolve_model("gateway:vendor-model", None)
            .unwrap(),
        ModelSelection {
            provider_id: "gateway".into(),
            model_id: "vendor-model".into(),
        }
    );
}

#[test]
fn enabled_catalog_without_snapshot_fails_closed() {
    let entry = offline_entry("catalogued", AdapterKind::OpenAiCompatibleChat, true);
    let health = ProviderHealthStore::new(4);
    health.mark_ready(entry.id());
    let directory = ProviderDirectory {
        entries: Arc::new(vec![entry]),
        health,
        deferred: None,
        refresh_activity: ProviderRefreshActivity::default(),
    };
    assert!(
        directory
            .resolve_model("catalogued:made-up", None)
            .unwrap_err()
            .contains("no usable model catalog")
    );
}
