# Version 1 compatibility fixtures

Use the [protocol specification](../../docs/HELPER_PROTOCOL.md) and
[message schema](message.schema.json) together. The fixtures are JSON data for
both Go and C# consumers. They do not require either implementation to exist.

All keys, endpoints, process IDs and metrics in the fixtures are public test
data. The example private key is published test material and is unsuitable for
deployment.

## Fixture files

| File | Scope |
| --- | --- |
| [frames.json](fixtures/frames.json) | Byte framing and strict JSON, before envelope or operation checks |
| [message-shapes.json](fixtures/message-shapes.json) | Draft 2020-12 schema acceptance and rejection |
| [sessions.json](fixtures/sessions.json) | Ordered controller/helper transcripts and controller timeout decisions |

Each file contains an array of cases with a stable `id`.

For a frame case, concatenate its `parts` as bytes in order. A `text` part is
UTF-8 encoded. A `hex` part contributes the decoded bytes. `repeat` defaults to
`1` and repeats a part after encoding. Each case ends with EOF. `expect` is
`accepted` for a decoded object or the required framing error code. A decoded
object can still fail subsequent envelope, schema or semantic checks.

For a message-shape case, validate `message` against the root schema. `valid`
is the expected outcome. Schema validation operates on a decoded object.

For a session case, interpret each step in order:

| Step | Meaning |
| --- | --- |
| `send` | Controller writes the object as a request line |
| `receive` | Expected helper response object, independent of key order |
| `deadline` | The controller's response deadline expired for this request ID |
| `decision` | After the specified status reply, the controller determines whether the timed-out mutation applied |
| `eof` | Controller closes stdin |
| `exit` | Helper process exits with the specified status, where `1` denotes any nonzero exit |

Controller tests can script these responses with a fake helper. Helper tests can
fix process IDs, clocks, selected ports and runtime outcomes in the harness, or
assert their relationships when testing a real process. Inject timeout and
failure events where possible instead of making tests wait for wall-clock
deadlines. Some `send` steps intentionally fail the message schema or the
session rules. Preserve those inputs when checking rejection behavior.

## Verify the shared data

From the repository root, with Python 3 and `jsonschema` available:

```text
python protocol/v1/verify_fixtures.py
```

The check validates the schema, frame outcomes, message-shape expectations and
transcript integrity, including correlation and revision/peer evidence for
reconciliation. It does not run a helper or a Jellyfin instance. The Python
package is needed only for this fixture check.
