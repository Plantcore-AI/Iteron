//! Content-free decoder diagnostics. Only closed enums and a frame ordinal can cross this
//! boundary; response values, parser messages, URLs and dynamic JSON keys cannot be retained.

use crate::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeCode {
    InvalidResponse,
    JsonSyntax,
    JsonEof,
    InvalidType,
    MissingField,
    InvalidValue,
    ConflictingValue,
    ProtocolSequence,
    LimitExceeded,
    InvalidUtf8,
}

impl DecodeCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidResponse => "invalid_response",
            Self::JsonSyntax => "json_syntax",
            Self::JsonEof => "json_eof",
            Self::InvalidType => "invalid_type",
            Self::MissingField => "missing_field",
            Self::InvalidValue => "invalid_value",
            Self::ConflictingValue => "conflicting_value",
            Self::ProtocolSequence => "protocol_sequence",
            Self::LimitExceeded => "limit_exceeded",
            Self::InvalidUtf8 => "invalid_utf8",
        }
    }
}

/// Schema-owned paths, never derived by copying a key or value from a response. `*` denotes
/// an array member. Unknown legacy failure locations intentionally report the response root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeField {
    Response,
    SseData,
    SseEvent,
    Usage,
    PromptTokens,
    CompletionTokens,
    PromptDetails,
    CachedTokens,
    CacheCreationTokens,
    CacheWriteTokens,
    CompletionDetails,
    ReasoningTokens,
    FinishReason,
    ChatTools,
    ChatToolId,
    ChatToolName,
    ChatToolArguments,
    ChatReasoningContent,
    ChatEncryptedContent,
    BaseResponseStatus,
    BaseResponseStatusCamel,
    Type,
    Delta,
    OutputIndex,
    ContentIndex,
    SummaryIndex,
    ItemId,
    CallId,
    Name,
    Arguments,
    ResponseOutput,
    ResponseInputTokens,
    ResponseOutputTokens,
    ResponseCachedTokens,
    ResponseCacheWriteTokens,
    ResponseReasoningTokens,
    Status,
    MessageUsage,
    InputTokens,
    OutputTokens,
    CacheReadInputTokens,
    CacheCreationInputTokens,
    ContentBlock,
    ContentBlockType,
    ContentBlockInput,
    Index,
    Text,
    Thinking,
    Signature,
    Data,
    Id,
    PartialJson,
    StopReason,
}

impl DecodeField {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Response => "$",
            Self::SseData => "sse.data",
            Self::SseEvent => "sse.event",
            Self::Usage => "$.usage",
            Self::PromptTokens => "$.usage.prompt_tokens",
            Self::CompletionTokens => "$.usage.completion_tokens",
            Self::PromptDetails => "$.usage.prompt_tokens_details",
            Self::CachedTokens => "$.usage.prompt_tokens_details.cached_tokens",
            Self::CacheCreationTokens => "$.usage.prompt_tokens_details.cache_creation_tokens",
            Self::CacheWriteTokens => "$.usage.prompt_tokens_details.cache_write_tokens",
            Self::CompletionDetails => "$.usage.completion_tokens_details",
            Self::ReasoningTokens => "$.usage.completion_tokens_details.reasoning_tokens",
            Self::FinishReason => "$.choices[0].finish_reason",
            Self::ChatTools => "$.choices[0].delta.tool_calls",
            Self::ChatToolId => "$.choices[0].delta.tool_calls[*].id",
            Self::ChatToolName => "$.choices[0].delta.tool_calls[*].function.name",
            Self::ChatToolArguments => "$.choices[0].delta.tool_calls[*].function.arguments",
            Self::ChatReasoningContent => "$.choices[0].delta.reasoning_content",
            Self::ChatEncryptedContent => "$.choices[0].delta.encrypted_content",
            Self::BaseResponseStatus => "$.base_resp.status_code",
            Self::BaseResponseStatusCamel => "$.baseResp.statusCode",
            Self::Type => "$..type",
            Self::Delta => "$.delta",
            Self::OutputIndex => "$.output_index",
            Self::ContentIndex => "$.content_index",
            Self::SummaryIndex => "$.summary_index",
            Self::ItemId => "$.item_id",
            Self::CallId => "$..call_id",
            Self::Name => "$..name",
            Self::Arguments => "$..arguments",
            Self::ResponseOutput => "$.response.output",
            Self::ResponseInputTokens => "$.response.usage.input_tokens",
            Self::ResponseOutputTokens => "$.response.usage.output_tokens",
            Self::ResponseCachedTokens => "$.response.usage.input_tokens_details.cached_tokens",
            Self::ResponseCacheWriteTokens => {
                "$.response.usage.input_tokens_details.cache_write_tokens"
            }
            Self::ResponseReasoningTokens => {
                "$.response.usage.output_tokens_details.reasoning_tokens"
            }
            Self::Status => "$..status",
            Self::MessageUsage => "$.message.usage",
            Self::InputTokens => "$.message.usage.input_tokens",
            Self::OutputTokens => "$.usage.output_tokens",
            Self::CacheReadInputTokens => "$.message.usage.cache_read_input_tokens",
            Self::CacheCreationInputTokens => "$.message.usage.cache_creation_input_tokens",
            Self::ContentBlock => "$.content_block",
            Self::ContentBlockType => "$.content_block.type",
            Self::ContentBlockInput => "$.content_block.input",
            Self::Index => "$.index",
            Self::Text => "$..text",
            Self::Thinking => "$..thinking",
            Self::Signature => "$..signature",
            Self::Data => "$..data",
            Self::Id => "$..id",
            Self::PartialJson => "$.delta.partial_json",
            Self::StopReason => "$.delta.stop_reason",
        }
    }

    // A closed allowlist for helpers that take schema field names. Unknown strings are never
    // retained, even if a future caller accidentally passes a provider-controlled key.
    pub(crate) fn schema_key(key: &str) -> Self {
        match key {
            "type" => Self::Type,
            "status" => Self::Status,
            "delta" => Self::Delta,
            "output_index" => Self::OutputIndex,
            "content_index" => Self::ContentIndex,
            "summary_index" => Self::SummaryIndex,
            "item_id" => Self::ItemId,
            "call_id" => Self::CallId,
            "name" => Self::Name,
            "arguments" => Self::Arguments,
            "index" => Self::Index,
            "text" => Self::Text,
            "thinking" => Self::Thinking,
            "signature" => Self::Signature,
            "data" => Self::Data,
            "id" => Self::Id,
            "partial_json" => Self::PartialJson,
            "input_tokens" => Self::InputTokens,
            "output_tokens" => Self::OutputTokens,
            "cache_read_input_tokens" => Self::CacheReadInputTokens,
            "cache_creation_input_tokens" => Self::CacheCreationInputTokens,
            _ => Self::Response,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeDiagnostic {
    pub code: DecodeCode,
    pub field: DecodeField,
    /// One-based ordinal of a data-bearing SSE frame (Chat uses one data line per frame).
    /// Comments, blank separators and SSE metadata do not advance this ordinal. Incomplete
    /// or malformed wire data uses the next candidate frame ordinal.
    pub frame: Option<u64>,
}

impl DecodeDiagnostic {
    pub const fn new(code: DecodeCode, field: DecodeField) -> Self {
        Self {
            code,
            field,
            frame: None,
        }
    }

    pub(crate) fn json(error: &serde_json::Error, field: DecodeField) -> Self {
        let code = match error.classify() {
            serde_json::error::Category::Eof => DecodeCode::JsonEof,
            serde_json::error::Category::Syntax => DecodeCode::JsonSyntax,
            serde_json::error::Category::Data => DecodeCode::InvalidType,
            serde_json::error::Category::Io => DecodeCode::InvalidResponse,
        };
        Self::new(code, field)
    }

    pub(crate) fn at_frame(mut self, frame: u64) -> Self {
        // Deferred tool errors retain the original failing frame, not the terminal that made
        // the failure authoritative. A later wrapper must not overwrite that evidence.
        self.frame.get_or_insert(frame);
        self
    }
}

impl std::fmt::Display for DecodeDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "provider response was invalid [code={}, field={}",
            self.code.as_str(),
            self.field.as_str()
        )?;
        if let Some(frame) = self.frame {
            write!(f, ", frame={frame}")?;
        }
        write!(f, "]")
    }
}

pub(crate) fn invalid(code: DecodeCode, field: DecodeField) -> ProviderError {
    ProviderError::InvalidResponse(DecodeDiagnostic::new(code, field))
}

pub(crate) fn json(error: &serde_json::Error, field: DecodeField) -> ProviderError {
    ProviderError::InvalidResponse(DecodeDiagnostic::json(error, field))
}
