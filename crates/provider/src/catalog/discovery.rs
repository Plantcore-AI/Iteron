//! Bounded physical catalog and account discovery, including page admission and decoding.
use super::{
    AccountAvailability, AccountProbe, AccountProbeResult, AdapterKind, ApiRoot,
    BOUNDED_RESPONSE_INITIAL_BYTES, BalanceAvailability, CATALOG_PAGE_INITIAL_BYTES,
    CATALOG_PAGE_SIZE, CatalogSnapshot, CatalogStrategy, Compatibility, ErrorProfile,
    FIREWORKS_PAGE_SIZE, FIREWORKS_SERVERLESS_FILTER, FIREWORKS_SERVERLESS_MODELS_PATH,
    MAX_ACCOUNT_PAGES, MAX_ACCOUNT_PROBE_PAGE_BYTES, MAX_ACCOUNT_PROBE_TOTAL_BYTES, MAX_ACCOUNTS,
    MAX_CATALOG_MODELS, MAX_CATALOG_PAGES, MAX_DISPLAY_NAME_BYTES, MAX_FIREWORKS_CATALOG_ACCOUNTS,
    MAX_FIREWORKS_CATALOG_PAGES, MAX_FIREWORKS_DEPLOYED_MODELS, MAX_MODEL_ID_BYTES, MAX_PAGE_BYTES,
    MAX_PAGE_TOKEN_BYTES, MAX_TOTAL_BYTES, ModelDescriptor, PER_REQUEST_TIMEOUT, ProviderInstance,
    RawModel, Selectability, TOTAL_DISCOVERY_TIMEOUT, compatibility, model_family,
};
use crate::{ProviderError, api_error_from_response};
use futures_util::StreamExt;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

/// Discover all models visible to the configured credential within strict request, page, byte,
/// model, and wall-clock bounds. Missing credentials return before a client/request is created.
pub async fn discover_catalog(
    instance: &ProviderInstance,
) -> Result<CatalogSnapshot, ProviderError> {
    if let CatalogStrategy::Unsupported { reason } = &instance.catalog_strategy {
        return Err(ProviderError::UnsupportedCatalog {
            provider: instance.id.clone(),
            reason: reason.clone(),
        });
    }
    let credential = instance
        .credential()
        .ok_or_else(|| ProviderError::MissingCredential {
            provider: instance.id.clone(),
        })?;
    let client = instance.shared_http_client()?;
    let deadline = Instant::now()
        + iteron_tunables::param_duration(
            "provider.catalog.total_discovery_timeout",
            TOTAL_DISCOVERY_TIMEOUT,
        );
    match &instance.catalog_strategy {
        CatalogStrategy::AnthropicModels => {
            let raw = discover_anthropic(&client, instance, &credential, deadline).await?;
            Ok(CatalogSnapshot::from_raw(instance, raw))
        }
        CatalogStrategy::OpenAiModels => {
            let raw = discover_openai(&client, instance, &credential, deadline).await?;
            Ok(CatalogSnapshot::from_raw(instance, raw))
        }
        CatalogStrategy::FireworksControlPlane { api_root } => {
            let models =
                discover_fireworks(&client, instance, &credential, api_root, deadline).await?;
            Ok(CatalogSnapshot::from_descriptors(instance, models))
        }
        CatalogStrategy::Unsupported { .. } => unreachable!("handled before credential lookup"),
    }
}

/// Run a documented, bounded account probe. DeepSeek's balance endpoint is rooted at the
/// provider origin (`/user/balance`), not below the model API root (`/v1`). Fireworks account
/// state comes from the separately documented control plane selected by `CatalogStrategy`.
pub async fn probe_account(
    instance: &ProviderInstance,
    probe: AccountProbe,
) -> Result<AccountProbeResult, ProviderError> {
    let credential = instance
        .credential()
        .ok_or_else(|| ProviderError::MissingCredential {
            provider: instance.id.clone(),
        })?;
    let client = instance.shared_http_client()?;
    match probe {
        AccountProbe::DeepSeekBalance => {
            let endpoint = instance.api_root.origin_endpoint("user/balance")?;
            tokio::time::timeout(
                iteron_tunables::param_duration(
                    "provider.catalog.per_request_timeout",
                    PER_REQUEST_TIMEOUT,
                ),
                async {
                    let response = client
                        .get(endpoint)
                        .bearer_auth(credential)
                        .send()
                        .await
                        .map_err(|error| ProviderError::Http(error.to_string()))?;
                    if !response.status().is_success() {
                        return Err(api_error_from_response(
                            response,
                            instance.adapter,
                            instance.error_profile,
                        )
                        .await);
                    }
                    let bytes = read_bounded_response(
                        response,
                        iteron_tunables::param_integer(
                            "provider.catalog.max_account_probe_page_bytes",
                            MAX_ACCOUNT_PROBE_PAGE_BYTES,
                        ),
                        "account probe",
                    )
                    .await?;
                    let payload: DeepSeekBalance =
                        serde_json::from_slice(&bytes).map_err(|error| {
                            ProviderError::Decode(format!(
                                "malformed DeepSeek balance response: {error}"
                            ))
                        })?;
                    Ok(deepseek_probe_result(payload.is_available))
                },
            )
            .await
            .map_err(|_| ProviderError::Http("account probe timed out".into()))?
        }
        AccountProbe::FireworksSuspendState => {
            let CatalogStrategy::FireworksControlPlane { api_root } = &instance.catalog_strategy
            else {
                return Err(ProviderError::Configuration(
                    "Fireworks account probe requires an explicit Fireworks control-plane strategy"
                        .into(),
                ));
            };
            probe_fireworks_accounts(&client, instance, &credential, api_root).await
        }
    }
}

#[derive(Deserialize)]
pub(super) struct DeepSeekBalance {
    pub(super) is_available: bool,
}

pub(super) fn deepseek_probe_result(is_available: bool) -> AccountProbeResult {
    if is_available {
        AccountProbeResult {
            availability: AccountAvailability::Ready,
            balance: BalanceAvailability::Sufficient,
        }
    } else {
        AccountProbeResult {
            availability: AccountAvailability::BillingBlocked,
            balance: BalanceAvailability::Depleted,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FireworksRpcStatus {
    pub(super) code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FireworksAccount {
    pub(super) name: String,
    pub(super) state: Option<String>,
    pub(super) status: Option<FireworksRpcStatus>,
    pub(super) suspend_state: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FireworksAccountsPage {
    pub(super) accounts: Vec<FireworksAccount>,
    pub(super) next_page_token: Option<String>,
}

async fn probe_fireworks_accounts(
    client: &reqwest::Client,
    instance: &ProviderInstance,
    credential: &str,
    control_plane_root: &ApiRoot,
) -> Result<AccountProbeResult, ProviderError> {
    let endpoint = control_plane_root.endpoint("accounts")?;
    let deadline = Instant::now()
        + iteron_tunables::param_duration(
            "provider.catalog.total_discovery_timeout",
            TOTAL_DISCOVERY_TIMEOUT,
        );
    let mut accounts = Vec::new();
    let mut total_bytes = 0usize;
    let mut cursor: Option<String> = None;
    let mut seen_cursors = BTreeSet::new();

    let max_account_pages =
        iteron_tunables::param_usize("provider.catalog.max_account_pages", MAX_ACCOUNT_PAGES);
    for page_number in 0..max_account_pages {
        let mut request = client
            .get(endpoint.clone())
            .bearer_auth(credential)
            .query(&[(
                "pageSize",
                iteron_tunables::param_integer(
                    "provider.catalog.fireworks_page_size",
                    FIREWORKS_PAGE_SIZE,
                )
                .to_string(),
            )])
            .query(&[("readMask", "name,state,status,suspendState")]);
        if let Some(page_token) = &cursor {
            request = request.query(&[("pageToken", page_token)]);
        }
        let bytes = execute_account_request(
            request,
            instance.adapter,
            instance.error_profile,
            deadline,
            total_bytes,
        )
        .await?;
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| ProviderError::Decode("account probe byte counter overflow".into()))?;
        let page: FireworksAccountsPage = serde_json::from_slice(&bytes).map_err(|error| {
            ProviderError::Decode(format!("malformed Fireworks accounts response: {error}"))
        })?;
        for account in page.accounts {
            validate_model_text(
                &account.name,
                iteron_tunables::param_integer(
                    "provider.catalog.max_model_id_bytes",
                    MAX_MODEL_ID_BYTES,
                ),
                "account name",
            )?;
            accounts.push(account);
            if accounts.len()
                > iteron_tunables::param_usize("provider.catalog.max_accounts", MAX_ACCOUNTS)
            {
                return Err(ProviderError::Decode(
                    "Fireworks account probe exceeded account bound".into(),
                ));
            }
        }
        let Some(next) = advance_page_token(
            "Fireworks accounts",
            cursor.as_deref(),
            &mut seen_cursors,
            page.next_page_token,
        )?
        else {
            return Ok(aggregate_fireworks_accounts(accounts));
        };
        cursor = Some(next);
        if page_number + 1 == max_account_pages {
            return Err(ProviderError::Decode(
                "Fireworks account probe exceeded page bound".into(),
            ));
        }
    }
    Err(ProviderError::Decode(
        "Fireworks account probe exceeded page bound".into(),
    ))
}

async fn execute_account_request(
    request: reqwest::RequestBuilder,
    adapter: AdapterKind,
    error_profile: ErrorProfile,
    deadline: Instant,
    total_bytes_before: usize,
) -> Result<Vec<u8>, ProviderError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(ProviderError::Http("account probe timed out".into()));
    }
    let timeout = remaining.min(iteron_tunables::param_duration(
        "provider.catalog.per_request_timeout",
        PER_REQUEST_TIMEOUT,
    ));
    let bytes = tokio::time::timeout(timeout, async move {
        let response = request
            .send()
            .await
            .map_err(|error| ProviderError::Http(error.to_string()))?;
        if !response.status().is_success() {
            return Err(api_error_from_response(response, adapter, error_profile).await);
        }
        read_bounded_response(
            response,
            iteron_tunables::param_integer(
                "provider.catalog.max_account_probe_page_bytes",
                MAX_ACCOUNT_PROBE_PAGE_BYTES,
            ),
            "account probe page",
        )
        .await
    })
    .await
    .map_err(|_| ProviderError::Http("account probe request timed out".into()))??;
    let total = total_bytes_before
        .checked_add(bytes.len())
        .ok_or_else(|| ProviderError::Decode("account probe total size overflow".into()))?;
    if total
        > iteron_tunables::param_integer(
            "provider.catalog.max_account_probe_total_bytes",
            MAX_ACCOUNT_PROBE_TOTAL_BYTES,
        )
    {
        return Err(ProviderError::Decode(
            "account probe exceeded total byte bound".into(),
        ));
    }
    Ok(bytes)
}

pub(super) fn aggregate_fireworks_accounts(accounts: Vec<FireworksAccount>) -> AccountProbeResult {
    let mut by_account = BTreeMap::<String, AccountProbeResult>::new();
    for account in accounts {
        let result = fireworks_account_result(
            account.state.as_deref(),
            account
                .status
                .as_ref()
                .and_then(|status| status.code.as_deref()),
            account.suspend_state.as_deref(),
        );
        by_account
            .entry(account.name)
            .and_modify(|current| {
                if *current != result {
                    // Repeated resource names with inconsistent snapshots are not authoritative.
                    *current = unknown_account_probe_result();
                }
            })
            .or_insert(result);
    }
    let mut results = by_account.into_values();
    let Some(first) = results.next() else {
        return unknown_account_probe_result();
    };
    if results.all(|result| result == first) {
        first
    } else {
        // A key may expose more than one account. Conflicting account states do not identify which
        // one funds inference, so collapsing them to either funded or depleted would be a guess.
        unknown_account_probe_result()
    }
}

pub(super) fn fireworks_account_result(
    state: Option<&str>,
    status_code: Option<&str>,
    suspend_state: Option<&str>,
) -> AccountProbeResult {
    match suspend_state {
        Some("FAILED_PAYMENTS" | "CREDIT_DEPLETED" | "MONTHLY_SPEND_LIMIT_EXCEEDED") => {
            AccountProbeResult {
                availability: AccountAvailability::BillingBlocked,
                balance: BalanceAvailability::Depleted,
            }
        }
        Some("BLOCKED_BY_ABUSE_RULE") => AccountProbeResult {
            availability: AccountAvailability::PermissionBlocked,
            balance: BalanceAvailability::Unknown,
        },
        Some("UNSUSPENDED") if state == Some("READY") && status_code == Some("OK") => {
            AccountProbeResult {
                availability: AccountAvailability::Ready,
                // Not suspended is not proof of an exact positive remaining balance.
                balance: BalanceAvailability::Unknown,
            }
        }
        _ => unknown_account_probe_result(),
    }
}

pub(super) fn unknown_account_probe_result() -> AccountProbeResult {
    AccountProbeResult {
        availability: AccountAvailability::Unknown,
        balance: BalanceAvailability::Unknown,
    }
}

async fn read_bounded_response(
    response: reqwest::Response,
    max_bytes: usize,
    label: &'static str,
) -> Result<Vec<u8>, ProviderError> {
    let mut body = Vec::with_capacity(
        iteron_tunables::param_integer(
            "provider.catalog.bounded_response_initial_bytes",
            BOUNDED_RESPONSE_INITIAL_BYTES,
        )
        .min(max_bytes),
    );
    let mut stream = response.bytes_stream();
    while let Some(next) = stream.next().await {
        let chunk = next.map_err(|error| ProviderError::Http(error.to_string()))?;
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(ProviderError::Decode(format!(
                "{label} response exceeded byte bound"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn discover_anthropic(
    client: &reqwest::Client,
    instance: &ProviderInstance,
    credential: &str,
    deadline: Instant,
) -> Result<Vec<RawModel>, ProviderError> {
    let endpoint = instance.api_root.endpoint("models")?;
    let mut models = Vec::new();
    let mut total_bytes = 0usize;
    let mut cursor: Option<String> = None;
    let mut seen_cursors = BTreeSet::new();

    let max_catalog_pages =
        iteron_tunables::param_usize("provider.catalog.max_catalog_pages", MAX_CATALOG_PAGES);
    for page_number in 0..max_catalog_pages {
        let mut request = client
            .get(endpoint.clone())
            .header("x-api-key", credential)
            .header("anthropic-version", "2023-06-01")
            .query(&[(
                "limit",
                iteron_tunables::param_usize(
                    "provider.catalog.catalog_page_size",
                    iteron_tunables::param_integer(
                        "provider.catalog.catalog_page_size",
                        CATALOG_PAGE_SIZE,
                    ),
                )
                .to_string(),
            )]);
        if let Some(after_id) = &cursor {
            request = request.query(&[("after_id", after_id)]);
        }
        let bytes = execute_catalog_request(
            request,
            instance.adapter,
            instance.error_profile,
            deadline,
            total_bytes,
        )
        .await?;
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| ProviderError::Decode("catalog byte counter overflow".into()))?;
        let page: AnthropicModelsPage = decode_page(&bytes, total_bytes)?;
        for model in page.data {
            models.push(raw_anthropic_model(model)?);
            enforce_model_bound(models.len())?;
        }
        let Some(next) = advance_anthropic_cursor(
            cursor.as_deref(),
            &mut seen_cursors,
            page.has_more,
            page.last_id,
        )?
        else {
            return Ok(models);
        };
        cursor = Some(next);
        if page_number + 1 == max_catalog_pages {
            return Err(ProviderError::Decode(
                "Anthropic catalog exceeded page bound".into(),
            ));
        }
    }
    Err(ProviderError::Decode(
        "Anthropic catalog exceeded page bound".into(),
    ))
}

pub(super) fn advance_anthropic_cursor(
    current: Option<&str>,
    seen: &mut BTreeSet<String>,
    has_more: bool,
    last_id: Option<String>,
) -> Result<Option<String>, ProviderError> {
    if !has_more {
        return Ok(None);
    }
    let next = last_id.filter(|value| !value.is_empty()).ok_or_else(|| {
        ProviderError::Decode("Anthropic catalog has_more without last_id".into())
    })?;
    if current == Some(next.as_str()) || !seen.insert(next.clone()) {
        return Err(ProviderError::Decode(
            "Anthropic catalog cursor did not advance".into(),
        ));
    }
    Ok(Some(next))
}

async fn discover_openai(
    client: &reqwest::Client,
    instance: &ProviderInstance,
    credential: &str,
    deadline: Instant,
) -> Result<Vec<RawModel>, ProviderError> {
    let request = client
        .get(instance.api_root.endpoint("models")?)
        .bearer_auth(credential);
    let bytes = execute_catalog_request(
        request,
        instance.adapter,
        instance.error_profile,
        deadline,
        0,
    )
    .await?;
    let page: OpenAiModelsPage = decode_page(&bytes, bytes.len())?;
    enforce_model_bound(page.data.len())?;
    page.data.into_iter().map(raw_openai_model).collect()
}

async fn discover_fireworks(
    client: &reqwest::Client,
    instance: &ProviderInstance,
    credential: &str,
    control_plane_root: &ApiRoot,
    deadline: Instant,
) -> Result<Vec<ModelDescriptor>, ProviderError> {
    // Fireworks documents public serverless inventory under `accounts/fireworks/models`. It also
    // documents List Accounts and account-scoped List Models. Enumerating those private model
    // resources is safe. Dedicated deployment selectability is admitted only when List Deployed
    // Models returns a healthy default deployment, because only that documented state permits the
    // full model resource to be queried without inventing a `#deployment` routing suffix.
    let mut budget = FireworksCatalogBudget::default();
    let mut models = BTreeMap::new();
    discover_fireworks_models_at(
        client,
        instance,
        credential,
        control_plane_root,
        FIREWORKS_SERVERLESS_MODELS_PATH,
        Some(iteron_tunables::param_str(
            "provider.catalog.fireworks_serverless_filter",
            FIREWORKS_SERVERLESS_FILTER,
        )),
        FireworksModelScope::PublicServerless,
        "accounts/fireworks",
        None,
        None,
        deadline,
        &mut budget,
        &mut models,
    )
    .await?;

    let accounts = discover_fireworks_catalog_accounts(
        client,
        instance,
        credential,
        control_plane_root,
        deadline,
        &mut budget,
    )
    .await?;
    for (account, account_state) in accounts {
        if account == "accounts/fireworks" {
            continue;
        }
        let default_deployed_models = discover_fireworks_default_deployments(
            client,
            instance,
            credential,
            control_plane_root,
            &account,
            deadline,
            &mut budget,
        )
        .await?;
        discover_fireworks_models_at(
            client,
            instance,
            credential,
            control_plane_root,
            &format!("{account}/models"),
            None,
            FireworksModelScope::AccountPrivate,
            &account,
            Some(account_state),
            Some(&default_deployed_models),
            deadline,
            &mut budget,
            &mut models,
        )
        .await?;
    }
    Ok(models.into_values().collect())
}

#[derive(Default)]
struct FireworksCatalogBudget {
    pages: usize,
    total_bytes: usize,
    models: usize,
    deployed_models: usize,
}

impl FireworksCatalogBudget {
    fn record_page(&mut self, bytes: usize) -> Result<(), ProviderError> {
        self.pages = self
            .pages
            .checked_add(1)
            .ok_or_else(|| ProviderError::Decode("catalog page counter overflow".into()))?;
        if self.pages
            > iteron_tunables::param_integer(
                "provider.catalog.max_fireworks_catalog_pages",
                MAX_FIREWORKS_CATALOG_PAGES,
            )
        {
            return Err(ProviderError::Decode(
                "Fireworks catalog exceeded aggregate page bound".into(),
            ));
        }
        self.total_bytes = self
            .total_bytes
            .checked_add(bytes)
            .ok_or_else(|| ProviderError::Decode("catalog byte counter overflow".into()))?;
        if self.total_bytes
            > iteron_tunables::param_integer("provider.catalog.max_total_bytes", MAX_TOTAL_BYTES)
        {
            return Err(ProviderError::Decode(
                "Fireworks catalog exceeded aggregate byte bound".into(),
            ));
        }
        Ok(())
    }

    fn record_model(&mut self) -> Result<(), ProviderError> {
        self.models = self
            .models
            .checked_add(1)
            .ok_or_else(|| ProviderError::Decode("catalog model counter overflow".into()))?;
        enforce_model_bound(self.models)
    }

    fn record_deployed_model(&mut self) -> Result<(), ProviderError> {
        self.deployed_models = self.deployed_models.checked_add(1).ok_or_else(|| {
            ProviderError::Decode("Fireworks deployed-model counter overflow".into())
        })?;
        if self.deployed_models
            > iteron_tunables::param_integer(
                "provider.catalog.max_fireworks_deployed_models",
                MAX_FIREWORKS_DEPLOYED_MODELS,
            )
        {
            return Err(ProviderError::Decode(
                "Fireworks catalog exceeded deployed-model bound".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FireworksModelScope {
    PublicServerless,
    AccountPrivate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FireworksCatalogAccountState {
    pub(super) result: AccountProbeResult,
    pub(super) conflicting: bool,
}

#[allow(clippy::too_many_arguments)]
async fn discover_fireworks_models_at(
    client: &reqwest::Client,
    instance: &ProviderInstance,
    credential: &str,
    control_plane_root: &ApiRoot,
    resource_path: &str,
    filter: Option<&str>,
    scope: FireworksModelScope,
    expected_account: &str,
    account_state: Option<FireworksCatalogAccountState>,
    default_deployed_models: Option<&BTreeSet<String>>,
    deadline: Instant,
    budget: &mut FireworksCatalogBudget,
    models: &mut BTreeMap<String, ModelDescriptor>,
) -> Result<(), ProviderError> {
    let expected_owner = fireworks_account_id(expected_account)?;
    let endpoint = control_plane_root.endpoint(resource_path)?;
    let mut cursor: Option<String> = None;
    let mut seen_cursors = BTreeSet::new();

    loop {
        if budget.pages
            >= iteron_tunables::param_integer(
                "provider.catalog.max_fireworks_catalog_pages",
                MAX_FIREWORKS_CATALOG_PAGES,
            )
        {
            return Err(ProviderError::Decode(
                "Fireworks catalog exceeded aggregate page bound".into(),
            ));
        }
        let mut request = client
            .get(endpoint.clone())
            .bearer_auth(credential)
            .query(&[(
                "pageSize",
                iteron_tunables::param_integer(
                    "provider.catalog.fireworks_page_size",
                    FIREWORKS_PAGE_SIZE,
                )
                .to_string(),
            )]);
        if let Some(filter) = filter {
            request = request.query(&[("filter", filter)]);
        }
        if let Some(page_token) = &cursor {
            request = request.query(&[("pageToken", page_token)]);
        }
        let bytes = execute_catalog_request(
            request,
            instance.adapter,
            instance.error_profile,
            deadline,
            budget.total_bytes,
        )
        .await?;
        budget.record_page(bytes.len())?;
        let page: FireworksModelsPage = decode_page(&bytes, budget.total_bytes)?;
        for model in page.models {
            budget.record_model()?;
            validate_fireworks_model_parent(&model.name, expected_owner, "model")?;
            let has_default_deployment =
                default_deployed_models.is_some_and(|deployed| deployed.contains(&model.name));
            merge_fireworks_descriptor(
                models,
                describe_fireworks_model(model, scope, account_state, has_default_deployment)?,
            );
        }
        let Some(next) = advance_page_token(
            "Fireworks models",
            cursor.as_deref(),
            &mut seen_cursors,
            page.next_page_token,
        )?
        else {
            return Ok(());
        };
        cursor = Some(next);
    }
}

async fn discover_fireworks_default_deployments(
    client: &reqwest::Client,
    instance: &ProviderInstance,
    credential: &str,
    control_plane_root: &ApiRoot,
    account: &str,
    deadline: Instant,
    budget: &mut FireworksCatalogBudget,
) -> Result<BTreeSet<String>, ProviderError> {
    validate_fireworks_account_name(account)?;
    let endpoint = control_plane_root.endpoint(&format!("{account}/deployedModels"))?;
    let mut cursor: Option<String> = None;
    let mut seen_cursors = BTreeSet::new();
    // A model may have many named deployments, but Fireworks documents at most one effective
    // default route. Multiple default records are inconsistent control-plane evidence and fail
    // closed for that model leaf.
    let mut default_evidence = BTreeMap::<String, bool>::new();

    loop {
        if budget.pages
            >= iteron_tunables::param_integer(
                "provider.catalog.max_fireworks_catalog_pages",
                MAX_FIREWORKS_CATALOG_PAGES,
            )
        {
            return Err(ProviderError::Decode(
                "Fireworks catalog exceeded aggregate page bound".into(),
            ));
        }
        let mut request = client
            .get(endpoint.clone())
            .bearer_auth(credential)
            .query(&[(
                "pageSize",
                iteron_tunables::param_integer(
                    "provider.catalog.fireworks_page_size",
                    FIREWORKS_PAGE_SIZE,
                )
                .to_string(),
            )])
            .query(&[("readMask", "name,model,deployment,default,state,status")]);
        if let Some(page_token) = &cursor {
            request = request.query(&[("pageToken", page_token)]);
        }
        let bytes = execute_catalog_request(
            request,
            instance.adapter,
            instance.error_profile,
            deadline,
            budget.total_bytes,
        )
        .await?;
        budget.record_page(bytes.len())?;
        let page: FireworksDeployedModelsPage = decode_page(&bytes, budget.total_bytes)?;
        for deployed in page.deployed_models {
            budget.record_deployed_model()?;
            validate_fireworks_scoped_resource_name(
                &deployed.name,
                account,
                "deployedModels",
                "deployed model",
            )?;
            validate_fireworks_scoped_resource_name(
                &deployed.deployment,
                account,
                "deployments",
                "deployment",
            )?;
            validate_fireworks_model_parent(
                &deployed.model,
                fireworks_account_id(account)?,
                "deployed model",
            )?;
            if deployed.is_default {
                let healthy = deployed.state.as_deref() == Some("DEPLOYED")
                    && deployed
                        .status
                        .as_ref()
                        .and_then(|status| status.code.as_deref())
                        == Some("OK");
                use std::collections::btree_map::Entry;
                match default_evidence.entry(deployed.model) {
                    Entry::Vacant(entry) => {
                        entry.insert(healthy);
                    }
                    Entry::Occupied(mut entry) => {
                        // Duplicate defaults are ambiguous even if both currently look healthy.
                        entry.insert(false);
                    }
                }
            }
        }
        let Some(next) = advance_page_token(
            "Fireworks deployed models",
            cursor.as_deref(),
            &mut seen_cursors,
            page.next_page_token,
        )?
        else {
            return Ok(default_evidence
                .into_iter()
                .filter_map(|(model, healthy)| healthy.then_some(model))
                .collect());
        };
        cursor = Some(next);
    }
}

async fn discover_fireworks_catalog_accounts(
    client: &reqwest::Client,
    instance: &ProviderInstance,
    credential: &str,
    control_plane_root: &ApiRoot,
    deadline: Instant,
    budget: &mut FireworksCatalogBudget,
) -> Result<BTreeMap<String, FireworksCatalogAccountState>, ProviderError> {
    let endpoint = control_plane_root.endpoint("accounts")?;
    let mut accounts = BTreeMap::<String, FireworksCatalogAccountState>::new();
    let mut cursor: Option<String> = None;
    let mut seen_cursors = BTreeSet::new();
    loop {
        if budget.pages
            >= iteron_tunables::param_integer(
                "provider.catalog.max_fireworks_catalog_pages",
                MAX_FIREWORKS_CATALOG_PAGES,
            )
        {
            return Err(ProviderError::Decode(
                "Fireworks catalog exceeded aggregate page bound".into(),
            ));
        }
        let mut request = client
            .get(endpoint.clone())
            .bearer_auth(credential)
            .query(&[(
                "pageSize",
                iteron_tunables::param_integer(
                    "provider.catalog.fireworks_page_size",
                    FIREWORKS_PAGE_SIZE,
                )
                .to_string(),
            )])
            .query(&[("readMask", "name,state,status,suspendState")]);
        if let Some(page_token) = &cursor {
            request = request.query(&[("pageToken", page_token)]);
        }
        let bytes = execute_catalog_request(
            request,
            instance.adapter,
            instance.error_profile,
            deadline,
            budget.total_bytes,
        )
        .await?;
        budget.record_page(bytes.len())?;
        let page: FireworksAccountsPage = decode_page(&bytes, budget.total_bytes)?;
        for account in page.accounts {
            validate_fireworks_account_name(&account.name)?;
            let result = fireworks_account_result(
                account.state.as_deref(),
                account
                    .status
                    .as_ref()
                    .and_then(|status| status.code.as_deref()),
                account.suspend_state.as_deref(),
            );
            accounts
                .entry(account.name)
                .and_modify(|current| {
                    if current.result != result {
                        current.result = unknown_account_probe_result();
                        current.conflicting = true;
                    }
                })
                .or_insert(FireworksCatalogAccountState {
                    result,
                    conflicting: false,
                });
            if accounts.len()
                > iteron_tunables::param_integer(
                    "provider.catalog.max_fireworks_catalog_accounts",
                    MAX_FIREWORKS_CATALOG_ACCOUNTS,
                )
            {
                return Err(ProviderError::Decode(
                    "Fireworks catalog exceeded account bound".into(),
                ));
            }
        }
        let Some(next) = advance_page_token(
            "Fireworks catalog accounts",
            cursor.as_deref(),
            &mut seen_cursors,
            page.next_page_token,
        )?
        else {
            return Ok(accounts);
        };
        cursor = Some(next);
    }
}

fn merge_fireworks_descriptor(
    models: &mut BTreeMap<String, ModelDescriptor>,
    descriptor: ModelDescriptor,
) {
    use std::collections::btree_map::Entry;
    match models.entry(descriptor.raw.id.clone()) {
        Entry::Vacant(entry) => {
            entry.insert(descriptor);
        }
        Entry::Occupied(mut entry) if entry.get() != &descriptor => {
            let raw = std::cmp::min(entry.get().raw.clone(), descriptor.raw);
            entry.insert(ModelDescriptor {
                family_id: model_family(&raw.id),
                raw,
                compatibility: Compatibility::Unknown,
                selectability: Selectability::Disabled {
                    reason: "Fireworks returned conflicting metadata for this model",
                },
            });
        }
        Entry::Occupied(_) => {}
    }
}

pub(super) fn advance_page_token(
    label: &'static str,
    current: Option<&str>,
    seen: &mut BTreeSet<String>,
    next: Option<String>,
) -> Result<Option<String>, ProviderError> {
    let Some(next) = next.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if next.len()
        > iteron_tunables::param_integer(
            "provider.catalog.max_page_token_bytes",
            MAX_PAGE_TOKEN_BYTES,
        )
        || next.chars().any(char::is_control)
    {
        return Err(ProviderError::Decode(format!(
            "{label} page token is invalid"
        )));
    }
    if current == Some(next.as_str()) || !seen.insert(next.clone()) {
        return Err(ProviderError::Decode(format!(
            "{label} page token did not advance"
        )));
    }
    Ok(Some(next))
}

async fn execute_catalog_request(
    request: reqwest::RequestBuilder,
    adapter: AdapterKind,
    error_profile: ErrorProfile,
    deadline: Instant,
    total_bytes_before: usize,
) -> Result<Vec<u8>, ProviderError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(ProviderError::Http("catalog discovery timed out".into()));
    }
    let timeout = remaining.min(iteron_tunables::param_duration(
        "provider.catalog.per_request_timeout",
        PER_REQUEST_TIMEOUT,
    ));
    tokio::time::timeout(timeout, async move {
        let response = request
            .send()
            .await
            .map_err(|error| ProviderError::Http(error.to_string()))?;
        if !response.status().is_success() {
            return Err(api_error_from_response(response, adapter, error_profile).await);
        }
        read_catalog_body(response, total_bytes_before).await
    })
    .await
    .map_err(|_| ProviderError::Http("catalog request timed out".into()))?
}

async fn read_catalog_body(
    response: reqwest::Response,
    total_bytes_before: usize,
) -> Result<Vec<u8>, ProviderError> {
    let mut body = Vec::with_capacity(iteron_tunables::param_integer(
        "provider.catalog.catalog_page_initial_bytes",
        CATALOG_PAGE_INITIAL_BYTES,
    ));
    let mut stream = response.bytes_stream();
    while let Some(next) = stream.next().await {
        let chunk = next.map_err(|error| ProviderError::Http(error.to_string()))?;
        let page_size = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| ProviderError::Decode("catalog page size overflow".into()))?;
        let total_size = total_bytes_before
            .checked_add(page_size)
            .ok_or_else(|| ProviderError::Decode("catalog total size overflow".into()))?;
        if page_size
            > iteron_tunables::param_integer("provider.catalog.max_page_bytes", MAX_PAGE_BYTES)
        {
            return Err(ProviderError::Decode(
                "provider catalog page exceeded 2 MiB".into(),
            ));
        }
        if total_size
            > iteron_tunables::param_integer("provider.catalog.max_total_bytes", MAX_TOTAL_BYTES)
        {
            return Err(ProviderError::Decode(
                "provider catalog exceeded 8 MiB".into(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub(super) fn decode_page<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    total_bytes: usize,
) -> Result<T, ProviderError> {
    if bytes.len()
        > iteron_tunables::param_integer("provider.catalog.max_page_bytes", MAX_PAGE_BYTES)
        || total_bytes
            > iteron_tunables::param_integer("provider.catalog.max_total_bytes", MAX_TOTAL_BYTES)
    {
        return Err(ProviderError::Decode(
            "provider catalog response exceeded byte bounds".into(),
        ));
    }
    serde_json::from_slice(bytes)
        .map_err(|error| ProviderError::Decode(format!("malformed provider catalog: {error}")))
}

fn enforce_model_bound(count: usize) -> Result<(), ProviderError> {
    if count
        > iteron_tunables::param_usize("provider.catalog.max_catalog_models", MAX_CATALOG_MODELS)
    {
        Err(ProviderError::Decode(
            "provider catalog exceeded model bound".into(),
        ))
    } else {
        Ok(())
    }
}

#[derive(Deserialize)]
pub(super) struct AnthropicModelsPage {
    pub(super) data: Vec<AnthropicModel>,
    pub(super) has_more: bool,
    pub(super) last_id: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct AnthropicModel {
    pub(super) id: String,
    pub(super) display_name: Option<String>,
    pub(super) created_at: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct OpenAiModelsPage {
    pub(super) data: Vec<OpenAiModel>,
}

#[derive(Deserialize)]
pub(super) struct OpenAiModel {
    pub(super) id: String,
    pub(super) created: Option<u64>,
    pub(super) owned_by: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FireworksModelsPage {
    pub(super) models: Vec<FireworksModel>,
    pub(super) next_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FireworksDeployedModelsPage {
    deployed_models: Vec<FireworksDeployedModel>,
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FireworksDeployedModel {
    name: String,
    model: String,
    deployment: String,
    #[serde(rename = "default", default)]
    is_default: bool,
    state: Option<String>,
    status: Option<FireworksRpcStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FireworksBaseModelDetails {
    pub(super) model_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct FireworksModel {
    pub(super) name: String,
    pub(super) display_name: Option<String>,
    pub(super) create_time: Option<String>,
    pub(super) state: Option<String>,
    pub(super) status: Option<FireworksRpcStatus>,
    pub(super) kind: Option<String>,
    pub(super) base_model_details: Option<FireworksBaseModelDetails>,
    pub(super) public: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_conversation_config")]
    pub(super) conversation_config: bool,
    pub(super) supports_tools: Option<bool>,
    pub(super) supports_serverless: Option<bool>,
    pub(super) supports_image_input: Option<bool>,
}

fn deserialize_conversation_config<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    match value {
        None => Ok(false),
        Some(serde_json::Value::Object(_)) => Ok(true),
        Some(_) => Err(serde::de::Error::custom(
            "Fireworks conversationConfig must be an object or null",
        )),
    }
}

fn raw_anthropic_model(model: AnthropicModel) -> Result<RawModel, ProviderError> {
    validate_model_text(
        &model.id,
        iteron_tunables::param_integer("provider.catalog.max_model_id_bytes", MAX_MODEL_ID_BYTES),
        "model id",
    )?;
    if let Some(display_name) = &model.display_name {
        validate_model_text(
            display_name,
            iteron_tunables::param_integer(
                "provider.catalog.max_display_name_bytes",
                MAX_DISPLAY_NAME_BYTES,
            ),
            "model display name",
        )?;
    }
    Ok(RawModel {
        id: model.id,
        display_name: model.display_name,
        created_at: model.created_at,
        owned_by: Some("anthropic".into()),
        supports_image_input: None,
    })
}

pub(super) fn raw_openai_model(model: OpenAiModel) -> Result<RawModel, ProviderError> {
    validate_model_text(
        &model.id,
        iteron_tunables::param_integer("provider.catalog.max_model_id_bytes", MAX_MODEL_ID_BYTES),
        "model id",
    )?;
    if let Some(owner) = &model.owned_by {
        validate_model_text(
            owner,
            iteron_tunables::param_integer(
                "provider.catalog.max_display_name_bytes",
                MAX_DISPLAY_NAME_BYTES,
            ),
            "model owner",
        )?;
    }
    Ok(RawModel {
        display_name: Some(model.id.clone()),
        id: model.id,
        created_at: model.created.map(|value| value.to_string()),
        owned_by: model.owned_by,
        supports_image_input: None,
    })
}

pub(super) fn describe_fireworks_model(
    model: FireworksModel,
    scope: FireworksModelScope,
    account_state: Option<FireworksCatalogAccountState>,
    has_default_deployment: bool,
) -> Result<ModelDescriptor, ProviderError> {
    validate_model_text(
        &model.name,
        iteron_tunables::param_integer("provider.catalog.max_model_id_bytes", MAX_MODEL_ID_BYTES),
        "model id",
    )?;
    if let Some(display_name) = &model.display_name {
        validate_model_text(
            display_name,
            iteron_tunables::param_integer(
                "provider.catalog.max_display_name_bytes",
                MAX_DISPLAY_NAME_BYTES,
            ),
            "model display name",
        )?;
    }
    let (owner, _) = parse_fireworks_model_name(&model.name)?;
    let owned_by = Some(owner.to_string());

    let incompatible_kind = model.kind.as_deref() == Some("EMBEDDING_MODEL");
    let incompatible_type = model
        .base_model_details
        .as_ref()
        .and_then(|details| details.model_type.as_deref())
        .is_some_and(non_agent_model_type);
    let compatibility = if incompatible_kind
        || incompatible_type
        || !model.conversation_config
        || model.supports_tools != Some(true)
    {
        Compatibility::Incompatible
    } else {
        Compatibility::Compatible
    };

    let selectability = if account_state.is_some_and(|state| state.conflicting) {
        Selectability::Disabled {
            reason: "Fireworks account metadata is conflicting",
        }
    } else if account_state.is_some_and(|state| {
        state.result.balance == BalanceAvailability::Depleted
            || state.result.availability == AccountAvailability::BillingBlocked
    }) {
        Selectability::Disabled {
            reason: "Fireworks account billing is blocked",
        }
    } else if account_state
        .is_some_and(|state| state.result.availability == AccountAvailability::PermissionBlocked)
    {
        Selectability::Disabled {
            reason: "Fireworks account permission is blocked",
        }
    } else if model.state.as_deref() != Some("READY") {
        Selectability::Disabled {
            reason: "Fireworks model is not ready",
        }
    } else if model
        .status
        .as_ref()
        .and_then(|status| status.code.as_deref())
        != Some("OK")
    {
        Selectability::Disabled {
            reason: "Fireworks model status is not OK",
        }
    } else if model.supports_serverless != Some(true)
        && !(scope == FireworksModelScope::AccountPrivate && has_default_deployment)
    {
        Selectability::Disabled {
            reason: match scope {
                FireworksModelScope::PublicServerless => {
                    "Fireworks model has no serverless deployment"
                }
                FireworksModelScope::AccountPrivate => {
                    "private model has no healthy default deployment; Core does not infer #deployment routing"
                }
            },
        }
    } else if scope == FireworksModelScope::PublicServerless && model.public != Some(true) {
        Selectability::Disabled {
            reason: "Fireworks public catalog model is not marked public",
        }
    } else if !model.conversation_config {
        Selectability::Disabled {
            reason: "Fireworks Chat Completions is not enabled for this model",
        }
    } else if incompatible_kind || incompatible_type {
        Selectability::Disabled {
            reason: "model is not a coding-turn model",
        }
    } else if model.supports_tools != Some(true) {
        Selectability::Disabled {
            reason: "Fireworks model does not advertise tool calling",
        }
    } else {
        Selectability::Selectable
    };

    let raw = RawModel {
        id: model.name,
        display_name: model.display_name,
        created_at: model.create_time,
        owned_by,
        supports_image_input: model.supports_image_input,
    };
    Ok(ModelDescriptor {
        family_id: model_family(&raw.id),
        raw,
        compatibility,
        selectability,
    })
}

fn validate_fireworks_account_name(account_name: &str) -> Result<(), ProviderError> {
    fireworks_account_id(account_name).map(|_| ())
}

fn fireworks_account_id(account_name: &str) -> Result<&str, ProviderError> {
    let mut segments = account_name.split('/');
    let (Some("accounts"), Some(account), None) =
        (segments.next(), segments.next(), segments.next())
    else {
        return Err(ProviderError::Decode(
            "Fireworks returned an invalid account resource name".into(),
        ));
    };
    if !valid_fireworks_resource_id(account) {
        return Err(ProviderError::Decode(
            "Fireworks returned an invalid account resource name".into(),
        ));
    }
    Ok(account)
}

fn validate_fireworks_scoped_resource_name(
    resource_name: &str,
    account_name: &str,
    collection: &str,
    label: &str,
) -> Result<(), ProviderError> {
    let mut account_segments = account_name.split('/');
    let (Some("accounts"), Some(expected_account), None) = (
        account_segments.next(),
        account_segments.next(),
        account_segments.next(),
    ) else {
        return Err(ProviderError::Decode(
            "Fireworks returned an invalid account resource name".into(),
        ));
    };
    let mut segments = resource_name.split('/');
    let valid = matches!(segments.next(), Some("accounts"))
        && segments.next() == Some(expected_account)
        && segments.next() == Some(collection)
        && segments.next().is_some_and(valid_fireworks_resource_id)
        && segments.next().is_none();
    if valid {
        Ok(())
    } else {
        Err(ProviderError::Decode(format!(
            "Fireworks returned an invalid {label} resource name"
        )))
    }
}

fn parse_fireworks_model_name(model_name: &str) -> Result<(&str, &str), ProviderError> {
    let mut segments = model_name.split('/');
    let (Some("accounts"), Some(account), Some("models"), Some(model_id), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(ProviderError::Decode(
            "Fireworks returned an invalid full model resource name".into(),
        ));
    };
    if !valid_fireworks_resource_id(account) || !valid_fireworks_resource_id(model_id) {
        return Err(ProviderError::Decode(
            "Fireworks returned an invalid full model resource name".into(),
        ));
    }
    Ok((account, model_id))
}

pub(super) fn validate_fireworks_model_parent(
    model_name: &str,
    expected_account: &str,
    label: &str,
) -> Result<(), ProviderError> {
    let (actual_account, _) = parse_fireworks_model_name(model_name)?;
    if actual_account != expected_account {
        return Err(ProviderError::Decode(format!(
            "Fireworks {label} resource escaped its requested account parent"
        )));
    }
    Ok(())
}

fn valid_fireworks_resource_id(value: &str) -> bool {
    (1..=63).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn non_agent_model_type(model_type: &str) -> bool {
    let model_type = model_type.to_ascii_lowercase();
    [
        "embedding",
        "rerank",
        "image",
        "audio",
        "video",
        "speech",
        "moderation",
    ]
    .iter()
    .any(|marker| model_type.contains(marker))
}

fn validate_model_text(value: &str, max_bytes: usize, field: &str) -> Result<(), ProviderError> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(ProviderError::Decode(format!(
            "provider catalog {field} is invalid"
        )));
    }
    Ok(())
}
