use crate::config::{ProviderConfig, ProviderCredential};
use iteron_provider::RecordingProviderTransport;
use std::io::Read;
use std::path::Path;

const REQUIRED_CREDENTIAL_ENV: &str = "ITERON_PROVIDER_API_KEY";
const MAX_CA_BYTES: u64 = 65_536;

pub(crate) fn prepare(
    path: &Path,
    configured: &[ProviderConfig],
    selected_provider_id: &str,
) -> anyhow::Result<RecordingProviderTransport> {
    validate_selected_provider(configured, selected_provider_id)?;
    let pem = read_bounded_regular_file(path)?;
    RecordingProviderTransport::from_pem(&pem)
        .map_err(|_| anyhow::anyhow!("recording_provider_ca_invalid_pem"))
}

fn validate_selected_provider(
    configured: &[ProviderConfig],
    selected_provider_id: &str,
) -> anyhow::Result<()> {
    let provider = configured
        .iter()
        .find(|provider| provider.id == selected_provider_id)
        .ok_or_else(|| anyhow::anyhow!("recording_provider_route_not_configured"))?;
    if provider.adapter != "openai_chat"
        || provider.catalog
        || provider.key_env.is_some()
        || !matches!(
            provider.credential.as_ref(),
            Some(ProviderCredential::Env { name }) if name == REQUIRED_CREDENTIAL_ENV
        )
        || !is_exact_loopback_origin(&provider.api_root)
    {
        anyhow::bail!("recording_provider_route_invalid");
    }
    Ok(())
}

fn is_exact_loopback_origin(value: &str) -> bool {
    let Some(port_text) = value
        .strip_prefix("https://127.0.0.1:")
        .and_then(|value| value.strip_suffix("/v1"))
    else {
        return false;
    };
    if port_text.is_empty()
        || port_text.starts_with('0')
        || port_text.len() > 5
        || !port_text.bytes().all(|byte| byte.is_ascii_digit())
        || port_text.parse::<u16>().is_err()
    {
        return false;
    }
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    url.scheme() == "https"
        && matches!(url.host(), Some(url::Host::Ipv4(address)) if address.octets() == [127, 0, 0, 1])
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/v1"
        && url.query().is_none()
        && url.fragment().is_none()
}

#[cfg(unix)]
fn read_bounded_regular_file(path: &Path) -> anyhow::Result<Vec<u8>> {
    use std::os::unix::fs::OpenOptionsExt as _;

    if !path.is_absolute() {
        anyhow::bail!("recording_provider_ca_path_not_absolute");
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| anyhow::anyhow!("recording_provider_ca_open_failed"))?;
    let metadata = file
        .metadata()
        .map_err(|_| anyhow::anyhow!("recording_provider_ca_metadata_failed"))?;
    if !metadata.file_type().is_file() {
        anyhow::bail!("recording_provider_ca_not_regular");
    }
    if !(1..=MAX_CA_BYTES).contains(&metadata.len()) {
        anyhow::bail!("recording_provider_ca_size_invalid");
    }
    let mut pem = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_CA_BYTES + 1)
        .read_to_end(&mut pem)
        .map_err(|_| anyhow::anyhow!("recording_provider_ca_read_failed"))?;
    if pem.len() as u64 != metadata.len() {
        anyhow::bail!("recording_provider_ca_changed_during_read");
    }
    Ok(pem)
}

#[cfg(not(unix))]
fn read_bounded_regular_file(_path: &Path) -> anyhow::Result<Vec<u8>> {
    anyhow::bail!("recording_provider_ca_unsupported_platform")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn provider(api_root: &str) -> ProviderConfig {
        ProviderConfig {
            id: "plantcore-recording".into(),
            display_name: Some("PlantCore recording provider".into()),
            adapter: "openai_chat".into(),
            error_profile: Some("custom".into()),
            api_root: api_root.into(),
            key_env: None,
            credential: Some(ProviderCredential::Env {
                name: REQUIRED_CREDENTIAL_ENV.into(),
            }),
            enabled: true,
            catalog: false,
            models: vec!["fixture-model".into()],
            model_capabilities: BTreeMap::new(),
        }
    }

    #[test]
    fn recording_origin_is_the_exact_ipv4_loopback_https_v1_shape() {
        assert!(is_exact_loopback_origin("https://127.0.0.1:443/v1"));
        for rejected in [
            "http://127.0.0.1:443/v1",
            "https://localhost:443/v1",
            "https://[::1]:443/v1",
            "https://user@127.0.0.1:443/v1",
            "https://127.0.0.1/v1",
            "https://127.0.0.1:0/v1",
            "https://127.0.0.1:0443/v1",
            "https://127.0.0.1:65536/v1",
            "https://127.0.0.1:443/v1/",
            "https://127.0.0.1:443/v1?x=1",
            "https://127.0.0.1:443/v1#x",
        ] {
            assert!(!is_exact_loopback_origin(rejected), "{rejected}");
        }
    }

    #[test]
    fn recording_route_requires_the_closed_adapter_catalog_and_credential_shape() {
        let accepted = provider("https://127.0.0.1:443/v1");
        assert!(validate_selected_provider(std::slice::from_ref(&accepted), &accepted.id).is_ok());

        let mut wrong_adapter = accepted.clone();
        wrong_adapter.adapter = "openai_responses".into();
        assert!(validate_selected_provider(&[wrong_adapter], &accepted.id).is_err());

        let mut legacy_credential = accepted.clone();
        legacy_credential.key_env = Some(REQUIRED_CREDENTIAL_ENV.into());
        assert!(validate_selected_provider(&[legacy_credential], &accepted.id).is_err());

        let mut catalog = accepted.clone();
        catalog.catalog = true;
        assert!(validate_selected_provider(&[catalog], &accepted.id).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn ca_reader_rejects_relative_empty_oversize_directory_and_symlink() {
        use std::os::unix::fs::symlink;

        let root =
            std::env::temp_dir().join(format!("iteron-recording-ca-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let empty = root.join("empty.pem");
        std::fs::write(&empty, []).unwrap();
        let oversize = root.join("oversize.pem");
        std::fs::write(&oversize, vec![b'x'; MAX_CA_BYTES as usize + 1]).unwrap();
        let maximum = root.join("maximum.pem");
        std::fs::write(&maximum, vec![b'x'; MAX_CA_BYTES as usize]).unwrap();
        let symlink_path = root.join("link.pem");
        symlink(&empty, &symlink_path).unwrap();

        assert!(read_bounded_regular_file(Path::new("relative.pem")).is_err());
        assert!(read_bounded_regular_file(&empty).is_err());
        assert_eq!(
            read_bounded_regular_file(&maximum).unwrap().len(),
            MAX_CA_BYTES as usize
        );
        assert!(read_bounded_regular_file(&oversize).is_err());
        assert!(read_bounded_regular_file(&root).is_err());
        assert!(read_bounded_regular_file(&symlink_path).is_err());

        std::fs::remove_dir_all(root).unwrap();
    }
}
