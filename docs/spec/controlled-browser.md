# Optional controlled browser and computer viewport

The host can explicitly install two effecting tools against an operator-selected local W3C
WebDriver: `browser` for navigation, DOM observation and CSS interaction; `computer` for actual
PNG screenshots, pointer clicks, wheel scrolling and a fixed set of keyboard keys. The computer
surface controls only that isolated browser viewport. A separate optional
[native desktop tool](native-desktop.md) controls an operator-selected macOS application.

The default registry installs neither tool and starts no driver, browser, proxy or network task.
`BrowserConfig::new` admits an explicit loopback HTTP driver endpoint and 1–32 exact web origins.
The remote end creates a fresh headless incognito Chrome session; existing sessions, cookies,
profile paths, scripts, executable paths and credential stores cannot be supplied by a model.
The host disables downloads and password storage in the requested Chrome preferences. An
operator must supply a compatible trusted driver; this feature does not download or launch one.

Every browser and computer action, including reads and screenshots, requires both
`CodeExecuting` and `IrreversibleExternal`. A blanket `browser` or `computer` grant does not
grant `browser:external` or `computer:external`. Plan, task/policy ceilings, explicit denies and
governing-trust restrictions remain in force. Approval is a host admission decision; JSON
fields cannot mint it. Login, form submission, Enter and clicks can be irreversible.

The browser uses an owned bounded proxy for the exact origins and immutable host egress policy.
Proxy connections are admitted only during one actual action and are closed across action
generations. DNS names resolving to private addresses are refused; an explicitly admitted IP
literal can identify a local application. These controls route a cooperative fresh browser;
they do not claim OS confinement against a compromised browser or driver. An action's driver
reply confirms that browser command, not successful rollback or every remote site's transaction.

Opaque page references identify the current observation, and closing references identify the
current session generation. Before an interaction the host rechecks actual URL and DOM digest.
Pages and pixels remain untrusted data. The model receives a bounded DOM preview; complete
observed HTML and native PNG capture remain separate host data, with real source/time, byte count,
digest and dimensions. PNG header bounds are not a secret-redaction or hostile-image safety proof.
Opaque raster data must be retained only through the private artifact owner; no pixel redaction
is asserted. A screenshot whose URL changes during capture is discarded.

Lost, cancelled or timed-out driver dispatches become `Unknown`, quarantine this owner and are
not automatically retried. If the actual session identity is known, an exact current closing
reference permits an explicitly admitted Close. A lost new-session reply can leave the identity
unknown; operator reconciliation of that owned driver is required. This checkpoint does not
provide durable browser recovery or claim cleanup of an unknown driver session.

The `browser::tests` cases use a physical HTTP remote-end fault oracle and an actual TCP proxy;
they are not native browser proof. The explicitly ignored native gate requires a real
`ITERON_TEST_WEBDRIVER_ENDPOINT` and exercises a controlled page, real PNG, pointer/key commands
and an actual form POST. All execution and platform evidence is deferred to the final candidate.

Command endpoints and screenshot semantics follow [W3C WebDriver](https://www.w3.org/TR/webdriver2/).

## Explicit operator bootstrap

Supply `--browser-webdriver http://127.0.0.1:9515/` together with one or more
`--browser-origin https://example.com`. The driver must already be running. These
flags install both optional surfaces; installing them starts no driver session or
page connection. Each physical action still requires the admitted capability
ceiling and its external operation permission. Project configuration cannot install
the driver or origins. PlantCore recording mode refuses these surfaces.

## Model pixels and private recovery

A confirmed screenshot can enter the transcript as `ToolImage`, explicitly an
untrusted tool observation. It names the actual successful `ToolDone`, physical
tenant/run, image hash, dimensions and observation time. Raw PNG bytes are retained
in the private artifact store; transcript image bytes are externalized into scoped
private CAS before JSONL storage. Images from an unknown tool terminal are omitted.
Fork recovery preserves physical origin and refuses ambiguous image attribution.

Model projection admits at most four images per tool-result message and 8 MiB of
base64 per image. A larger retained PNG remains downloadable, with its model
projection reported unavailable. The complete request also passes the immutable
image decoder, aggregate byte and multimodal token envelope. Pixel contents are
untrusted and are not redacted as text.

OpenAI Chat uses an explicitly labeled companion user image following the actual
tool messages; Responses uses a labeled `input_image`. These native wire roles do
not constitute a new operator submission. See the official
[OpenAI image-input formats](https://developers.openai.com/api/docs/guides/images-vision).
Anthropic nests the pixels inside the matching `tool_result`, following its
[tool-result image format](https://platform.claude.com/docs/en/agents-and-tools/tool-use/handle-tool-calls).

Native browser/process gates and final integration tests remain required. The
computer surface controls an isolated browser viewport. Native desktop observations retain
their distinct scope through publication, model projection and recovery.
