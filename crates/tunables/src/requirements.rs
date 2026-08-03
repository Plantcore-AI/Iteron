use crate::{CapabilityRequirement, Domain, ProviderRequirement, RequirementSpec};

const INFERENCE: &[CapabilityRequirement] = &[CapabilityRequirement::Inference];
const PROVIDER_CATALOG: &[CapabilityRequirement] = &[CapabilityRequirement::ProviderCatalog];
const PROVIDER_STREAMING: &[CapabilityRequirement] = &[CapabilityRequirement::ProviderStreaming];
const SERVICE_TIER: &[CapabilityRequirement] = &[CapabilityRequirement::ProviderServiceTier];
const PROMPT_CACHE: &[CapabilityRequirement] = &[CapabilityRequirement::ProviderPromptCache];
const MULTIMODAL: &[CapabilityRequirement] = &[CapabilityRequirement::ProviderMultimodal];
const REQUEST_COMPRESSION: &[CapabilityRequirement] =
    &[CapabilityRequirement::ProviderRequestCompression];
const REASONING: &[CapabilityRequirement] = &[CapabilityRequirement::Reasoning];
const BUDGET: &[CapabilityRequirement] = &[CapabilityRequirement::BudgetAccounting];
const CONTEXT: &[CapabilityRequirement] = &[CapabilityRequirement::ContextRead];
const MEMORY: &[CapabilityRequirement] = &[CapabilityRequirement::MemoryReadWrite];
const TOOLING: &[CapabilityRequirement] = &[CapabilityRequirement::ToolExecution];
const PERSISTENT_PROCESS: &[CapabilityRequirement] = &[CapabilityRequirement::PersistentProcess];
const BACKGROUND_JOB: &[CapabilityRequirement] = &[CapabilityRequirement::BackgroundJob];
const INTERACTIVE_STDIN: &[CapabilityRequirement] = &[CapabilityRequirement::InteractiveStdin];
const PROCESS_SIGNAL: &[CapabilityRequirement] = &[CapabilityRequirement::ProcessSignal];
const FILESYSTEM_WRITE: &[CapabilityRequirement] = &[CapabilityRequirement::FileSystemWrite];
const BINARY_INSPECTION: &[CapabilityRequirement] = &[CapabilityRequirement::BinaryInspection];
const LANGUAGE_SERVER: &[CapabilityRequirement] = &[CapabilityRequirement::LanguageServer];
const TOOL_CACHE: &[CapabilityRequirement] = &[CapabilityRequirement::ToolResultCache];
const VERIFICATION: &[CapabilityRequirement] = &[CapabilityRequirement::Verification];
const COLLABORATION: &[CapabilityRequirement] = &[CapabilityRequirement::AgentSpawn];
const MESSAGING: &[CapabilityRequirement] = &[CapabilityRequirement::AgentMessaging];
const WORKTREE: &[CapabilityRequirement] = &[CapabilityRequirement::WorktreeIsolation];
const RUNTIME: &[CapabilityRequirement] = &[CapabilityRequirement::RuntimeObservation];
const EXTENSIBILITY: &[CapabilityRequirement] = &[CapabilityRequirement::ExtensionDiscovery];
const MCP: &[CapabilityRequirement] = &[CapabilityRequirement::McpTransport];
const OAUTH: &[CapabilityRequirement] = &[CapabilityRequirement::OAuth];
const OBSERVABILITY: &[CapabilityRequirement] = &[CapabilityRequirement::EvidenceObservation];
const INTERFACE: &[CapabilityRequirement] = &[CapabilityRequirement::OperatorInteraction];
const EVALUATION: &[CapabilityRequirement] = &[CapabilityRequirement::Evaluation];
const GOVERNANCE: &[CapabilityRequirement] = &[CapabilityRequirement::AuthorityConfiguration];

const CATALOG_BUDGET: &[CapabilityRequirement] = &[
    CapabilityRequirement::ProviderCatalog,
    CapabilityRequirement::BudgetAccounting,
];
const CATALOG_RUNTIME: &[CapabilityRequirement] = &[
    CapabilityRequirement::ProviderCatalog,
    CapabilityRequirement::RuntimeObservation,
];
const CATALOG_AGENT: &[CapabilityRequirement] = &[
    CapabilityRequirement::ProviderCatalog,
    CapabilityRequirement::AgentSpawn,
];
const CATALOG_CONTEXT: &[CapabilityRequirement] = &[
    CapabilityRequirement::ProviderCatalog,
    CapabilityRequirement::ContextRead,
];
const MULTIMODAL_CONTEXT: &[CapabilityRequirement] = &[
    CapabilityRequirement::ProviderMultimodal,
    CapabilityRequirement::ContextRead,
];
const CONTEXT_VERIFY: &[CapabilityRequirement] = &[
    CapabilityRequirement::ContextRead,
    CapabilityRequirement::Verification,
];
const MEMORY_CONTEXT: &[CapabilityRequirement] = &[
    CapabilityRequirement::MemoryReadWrite,
    CapabilityRequirement::ContextRead,
];
const TOOL_CONTEXT: &[CapabilityRequirement] = &[
    CapabilityRequirement::ToolExecution,
    CapabilityRequirement::ContextRead,
];
const LSP_CONTEXT: &[CapabilityRequirement] = &[
    CapabilityRequirement::LanguageServer,
    CapabilityRequirement::ContextRead,
];
const VERIFY_CHECKPOINT: &[CapabilityRequirement] = &[
    CapabilityRequirement::Verification,
    CapabilityRequirement::WorkspaceCheckpoint,
];
const VERIFY_AGENT: &[CapabilityRequirement] = &[
    CapabilityRequirement::Verification,
    CapabilityRequirement::AgentSpawn,
];
const AGENT_CATALOG: &[CapabilityRequirement] = &[
    CapabilityRequirement::AgentSpawn,
    CapabilityRequirement::ProviderCatalog,
];
const AGENT_REASONING: &[CapabilityRequirement] = &[
    CapabilityRequirement::AgentSpawn,
    CapabilityRequirement::Reasoning,
];
const AGENT_TOOL: &[CapabilityRequirement] = &[
    CapabilityRequirement::AgentSpawn,
    CapabilityRequirement::ToolExecution,
];
const AGENT_MEMORY: &[CapabilityRequirement] = &[
    CapabilityRequirement::AgentSpawn,
    CapabilityRequirement::MemoryReadWrite,
];
const MCP_CONTEXT: &[CapabilityRequirement] = &[
    CapabilityRequirement::McpTransport,
    CapabilityRequirement::ContextRead,
];
const RESOURCE_CONTEXT: &[CapabilityRequirement] = &[
    CapabilityRequirement::McpResource,
    CapabilityRequirement::ContextRead,
];
const RATE_LIMIT_INFERENCE: &[CapabilityRequirement] = &[
    CapabilityRequirement::RateLimitObservation,
    CapabilityRequirement::Inference,
];
const PROMPT_CACHE_CONTEXT: &[CapabilityRequirement] = &[
    CapabilityRequirement::ProviderPromptCache,
    CapabilityRequirement::ContextRead,
];
const REPLAY_MESSAGING: &[CapabilityRequirement] = &[
    CapabilityRequirement::ReplayEvidence,
    CapabilityRequirement::AgentMessaging,
];

pub(crate) const fn requirements(ordinal: u16, domain: Domain) -> RequirementSpec {
    let capabilities = match ordinal {
        23 => PROMPT_CACHE,
        68 => MULTIMODAL,
        100 => MULTIMODAL_CONTEXT,
        158 => PROMPT_CACHE_CONTEXT,
        70 | 77 | 86 => PROVIDER_CATALOG,
        88 => CATALOG_BUDGET,
        89 => CATALOG_RUNTIME,
        90 | 95 => PROVIDER_STREAMING,
        91 => SERVICE_TIER,
        93 => CATALOG_AGENT,
        96 => CATALOG_CONTEXT,
        104 => CONTEXT_VERIFY,
        105 | 107 => MEMORY_CONTEXT,
        108 | 113 | 114 => PERSISTENT_PROCESS,
        109 | 110 => BACKGROUND_JOB,
        111 => INTERACTIVE_STDIN,
        112 => PROCESS_SIGNAL,
        116 => FILESYSTEM_WRITE,
        117 => TOOL_CONTEXT,
        118 => BINARY_INSPECTION,
        119 | 120 => LANGUAGE_SERVER,
        121 => LSP_CONTEXT,
        122 => TOOL_CACHE,
        129 | 130 => VERIFY_CHECKPOINT,
        131 => VERIFY_AGENT,
        133 => AGENT_CATALOG,
        134 => AGENT_REASONING,
        135 => AGENT_TOOL,
        136 => AGENT_MEMORY,
        143 => WORKTREE,
        145 => MESSAGING,
        147 | 149 | 150 | 151 => MCP,
        148 | 152 => MCP_CONTEXT,
        153 => OAUTH,
        154 => RESOURCE_CONTEXT,
        155 => REQUEST_COMPRESSION,
        157 => RATE_LIMIT_INFERENCE,
        160 => REPLAY_MESSAGING,
        _ => match domain {
            Domain::Provider => INFERENCE,
            Domain::Reasoning => REASONING,
            Domain::Budget => BUDGET,
            Domain::Context => CONTEXT,
            Domain::Memory => MEMORY,
            Domain::Tooling => TOOLING,
            Domain::Verification => VERIFICATION,
            Domain::Orchestration => COLLABORATION,
            Domain::Runtime => RUNTIME,
            Domain::Extensibility => EXTENSIBILITY,
            Domain::Observability => OBSERVABILITY,
            Domain::Interface => INTERFACE,
            Domain::Evaluation => EVALUATION,
            Domain::Governance => GOVERNANCE,
        },
    };
    let provider = if matches!(
        ordinal,
        1 | 2 | 3 | 4 | 19 | 20 | 21 | 23 | 26 | 70 | 77 | 82 | 86..=100 | 133 | 155..=158
    ) {
        ProviderRequirement::SelectedRoute
    } else {
        ProviderRequirement::None
    };
    RequirementSpec {
        provider,
        capabilities,
    }
}
