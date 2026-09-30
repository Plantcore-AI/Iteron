# Optional controlled browser and computer viewport

The host can explicitly install two effecting tools against an operator-selected local W3C
WebDriver: `browser` for navigation, DOM observation and CSS interaction; `computer` for actual
PNG screenshots, pointer clicks, wheel scrolling and a fixed set of keyboard keys. The computer
surface controls only that isolated browser viewport. OS desktop automation is not implemented.

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
