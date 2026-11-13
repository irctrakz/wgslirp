# Version 1 compatibility fixtures

Use the [protocol specification](../../docs/HELPER_PROTOCOL.md) and
[message schema](message.schema.json) together. The fixtures are JSON data for
both Go and C# consumers. They do not require either implementation to exist.

All keys, endpoints, process IDs and metrics in the fixtures are public test
data. The server key pair comes from section 6.1 of RFC 7748. The checker uses
this known pair to verify startup identity. The private key is unsuitable for
deployment. [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748#section-6.1)

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
`accepted` for a decoded object, `clean_eof` when no bytes are buffered, or
the required framing error code. A decoded object can still fail subsequent
envelope, schema or semantic checks.

For a message-shape case, validate `message` against the root schema. `valid`
is the expected outcome. Schema validation operates on a decoded object.

For a session case, interpret each step in order:

| Step | Meaning |
| --- | --- |
| `send` | Controller writes the object as a request line |
| `in_flight` | Test harness holds the named request after execution begins and before it can publish a result |
| `receive` | Expected helper response object, independent of key order |
| `deadline` | The controller's response deadline expired for this request ID |
| `decision` | With both replies available, the controller records the request's `outcome` and whether `desired_state_holds` |
| `eof` | Controller closes stdin |
| `stdout_failed` | Stdout becomes unusable. The string is the unterminated response prefix observed by the controller, or empty if no bytes reached it. |
| `cleanup_timeout` | The harness advances cleanup past the shutdown deadline before any terminal diagnostic is written |
| `exit` | Helper process exits with the specified status, where `1` denotes any nonzero exit |
| `unexpected_exit` | The process exits with the observed status without a terminal reply or controller termination, abandoning pending requests |
| `shutdown_grace_expired` | The controller has closed stdin and the process is still running after the shutdown grace period |
| `force_terminate` | The controller terminates its still-running helper after closing stdin and waiting the shutdown grace period |
| `reap` | The controller waits for the old process to exit and releases its process resources |
| `replace_helper` | The controller may launch a replacement after failed reconciliation or a control timeout, once the old helper is reaped |

Controller tests can script these responses with a fake helper. Helper tests can
fix process IDs, clocks, selected ports and runtime outcomes in the harness, or
assert their relationships when testing a real process. Inject timeout and
failure events where possible instead of making tests wait for wall-clock
deadlines. Some `send` steps intentionally fail the message schema or the
session rules. Preserve those inputs when checking rejection behavior.

For a held request, the harness releases the operation for teardown after
shutdown starts. Assert that no correlated response, readiness or revision is
published after that transition and that resources acquired before cancellation
are closed. The transcript records the wire outcome. Future helper tests can
verify cancellation and resource cleanup directly.

For `stdout_failed` with a nonempty prefix, the harness holds the response
write after that prefix reaches stdout. When shutdown interrupts the write,
assert that stdout closes with exactly the prefix and no further bytes. A
terminal failure can exit nonzero without a complete diagnostic.

After a peer mutation deadline, the controller may send one reconciliation
status request. The transcript must establish the outcome with a
`decision` before further requests. If status times out or the helper fails
during reconciliation, the controller closes stdin if it is still open and
reaps the old helper before replacement.

A deadline for another control request, such as `start`, also requires
closing stdin and reaping before replacement. A `force_terminate` event
still needs a subsequent `exit` and `reap` before replacement.

## Verify the shared data

From the repository root, with Python 3 and `jsonschema` available:

```text
python protocol/v1/verify_fixtures.py
```

The check validates the schema, frame outcomes, message-shape expectations and
transcript integrity, including error precedence, terminal responses, reserved
peer addresses, the complete applied peer set and startup identity. It does not
run a helper or a Jellyfin instance. The Python package is needed only for this
fixture check.
