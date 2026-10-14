# Optional native macOS desktop tool

`desktop` operates one native application selected by the operator through an already running
local Appium Mac2 driver. It is separate from the browser and computer viewport tools. Its
screenshot is the actual main display and can include other applications. Neither the screenshot
nor the application control provides an isolated operating system or a fresh application profile.

## Installation and commands

The default registry installs no desktop tool, driver or background task. The operator supplies
both flags at launch:

```sh
iteron --desktop-webdriver http://127.0.0.1:4723/ --desktop-bundle com.example.NativeFixture
```

The endpoint must be explicit loopback HTTP with a port and root path. Project configuration
and model arguments cannot choose the endpoint, application, driver session, launch arguments
or environment. PlantCore recording mode refuses installation. The driver requires its native
macOS prerequisites and operating system permissions; Iteron does not install or grant them.

The tool admits a closed set of commands:

| Action | Arguments | Behavior |
| --- | --- | --- |
| `open` | None | Create the driver session for the selected application and observe it. |
| `observe` | Current `view_ref` | Read application source and main-display pixels. |
| `click` | Current `view_ref`, accessibility `selector` | Click the identified native element. |
| `type` | Current `view_ref`, literal `text` | Type up to 4096 UTF-8 bytes into the application. |
| `key` | Current `view_ref`, closed `key` enum | Send Enter, Escape, Tab, Backspace or an arrow key. |
| `scroll` | Current `view_ref`, accessibility `selector`, `delta_y` | Scroll the identified element. |
| `close` | Current `view_ref` or returned `close_ref` | Delete the known driver session. |

The application is attached with `noReset` and `skipAppKill`. Closing the driver session does not
promise to terminate the application or undo an action. Selectors use native accessibility IDs;
pixel coordinates, direct shell/AppleScript driver methods, arbitrary driver methods, clipboard and
app switching are not admitted. An admitted UI action can still execute code through the selected
application, such as typing into a terminal. Screenshot pixels are not converted into guessed
native screen coordinates.

## Authority, ownership and observations

Each operation uses the existing host permission mechanism and immutable ceiling. Native UI
input may modify local files, trust configuration or publish externally, so calls require code
execution, local write, trust write and external-effect authority. Named denies, Plan and frozen
task ceilings remain effective. A model argument cannot mint approval.

One owner retains the native driver session, current view and quarantine state. Only one physical
operation is admitted at a time. The physical worker retains that slot when its observer is
dropped. Responses are bounded to 12 MiB, connection establishment to two seconds, session
creation to 180 seconds and ordinary driver requests to ten seconds; the whole operation has
a 200-second deadline. There is no automatic retry of an uncertain action.

Application XML is bounded to 1 MiB. The tool rechecks its digest before mutation and again
after capture. Changed application source requires a fresh observation. A returned `view_ref`
belongs to this owner, session generation and observed revision. It does not freeze other apps
or the screen; source consistency is not a guarantee that a native UI cannot race an action.

Successful observations label their scope `native_mac_desktop`, report application identity,
source/time, XML truncation, pixel hash and dimensions. Full XML and actual PNG bytes follow the
private artifact path. Only an actual successful tool terminal can authorize the matching image
observation. Model projection, private CAS and fork recovery retain the same physical run,
terminal sequence and desktop scope. A browser terminal cannot witness desktop pixels.

The XML and pixels are untrusted data. Pixels are retained exactly; no pixel secret redaction
is asserted. Existing image decoder, image count, aggregate byte and context admission apply
before provider dispatch. A text-only route reports the image as unavailable to the model.

Unknown transport outcomes quarantine the owner. If the session identity is known, the returned
`close_ref` permits an explicitly authorized close. If the session-creation reply is lost, the
session identity may be unknown and the operator must reconcile the local driver. This tool
does not provide durable native-session recovery across process restart.

## Verification and backend reference

The physical HTTP fixtures verify request ownership, stale-view refusal, original PNG identity,
operation permissions and lost-action quarantine. They do not prove native macOS execution.
The ignored `real_native_mac2_main_desktop_observation_and_session_close` gate needs the real
`ITERON_TEST_MAC2_ENDPOINT` and `ITERON_TEST_MAC2_BUNDLE`. Its execution on the final candidate
must be recorded before claiming native desktop support as verified.

Native commands follow the official [Mac2 execute methods](https://appium.github.io/appium-mac2-driver/latest/reference/execute-methods/),
session options follow [Mac2 capabilities](https://appium.github.io/appium-mac2-driver/latest/reference/capabilities/),
and setup follows the [driver overview](https://appium.github.io/appium-mac2-driver/latest/overview/).
