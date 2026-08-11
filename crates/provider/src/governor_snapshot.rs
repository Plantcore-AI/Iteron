//! Content-free provider-governor diagnostics.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderGovernorSnapshot {
    pub max_in_flight_per_route: usize,
    pub minimum_remaining_requests: u64,
    pub minimum_remaining_tokens: u64,
    pub reset_wait_max_ms: u64,
    pub circuit_failure_threshold: u16,
    pub circuit_open_ms: u64,
    pub circuit_half_open_probes: u16,
    pub circuit_success_threshold: u16,
    pub hedge_enabled: bool,
    pub hedge_delay_ms: u64,
    pub hedge_max_duplicates: u8,
    pub routes: Vec<RouteGovernorSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteGovernorSnapshot {
    pub route_id: String,
    pub in_flight: usize,
    pub circuit: RouteCircuitSnapshot,
    pub quota_observed: bool,
    pub quota_age_ms: Option<u64>,
    pub requests_remaining: Option<u64>,
    pub tokens_remaining: Option<u64>,
    pub reset_remaining_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteCircuitSnapshot {
    Closed { failures: u16 },
    Open { remaining_ms: u64 },
    HalfOpen { successes: u16, probes: u16 },
}
