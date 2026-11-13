"""Check W1 compatibility data without a helper executable or a Jellyfin server."""

import json
from pathlib import Path
import re

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parent
MAX_FRAME_BYTES = 65_536
MAX_DEPTH = 16
UINT64_MAX = 2**64 - 1
COUNTERS = {
    "rx_bytes", "tx_bytes", "tcp_flow_refusals", "pending_dial_refusals", "buffer_refusals"
}
PEER_OPERATIONS = {"peer_add", "peer_remove"}
OPERATIONS = PEER_OPERATIONS | {"validate", "start", "status", "stop"}


def require(condition, detail):
    if not condition:
        raise AssertionError(detail)


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key!r}")
        result[key] = value
    return result


def fixture_cases(name):
    cases = read_json(ROOT / "fixtures" / name)
    ids = [case["id"] for case in cases]
    require(cases and len(ids) == len(set(ids)), f"{name}: empty file or duplicate IDs")
    return cases


def decimal_integer(token):
    if re.fullmatch(r"0|[1-9][0-9]*", token) is None:
        raise ValueError("integer must use unsigned decimal digits")
    return int(token)


def check_depth(obj, depth=1):
    if isinstance(obj, (dict, list)):
        if depth > MAX_DEPTH:
            raise ValueError("nesting exceeds the frame limit")
        for value in obj.values() if isinstance(obj, dict) else obj:
            check_depth(value, depth + 1)


def frame_outcome(parts):
    raw = b"".join(
        (part["text"].encode("utf-8") if "text" in part else bytes.fromhex(part["hex"]))
        * part.get("repeat", 1)
        for part in parts
    )
    if not raw.endswith(b"\n"):
        return "invalid_frame"
    payload = raw[:-1].removesuffix(b"\r")
    if len(payload) > MAX_FRAME_BYTES:
        return "frame_too_large"
    if b"\n" in payload:
        return "invalid_frame"
    try:
        obj = json.loads(
            payload.decode("utf-8"), object_pairs_hook=unique_object,
            parse_int=decimal_integer, parse_float=decimal_integer, parse_constant=decimal_integer,
        )
        check_depth(obj)
        # Re-encoding catches lone surrogate escapes accepted by Python's JSON decoder.
        json.dumps(obj, ensure_ascii=False).encode("utf-8")
    except (ValueError, RecursionError):
        return "invalid_frame"
    return "accepted" if isinstance(obj, dict) else "invalid_frame"


def check_counters(obj):
    if isinstance(obj, dict):
        for field, value in obj.items():
            if field in COUNTERS and value is not None:
                require(int(value) <= UINT64_MAX, f"{field} exceeds uint64")
            check_counters(value)
    elif isinstance(obj, list):
        for value in obj:
            check_counters(value)


def check_reconciliation(decision, requests, replies, deadlines):
    mutation_id, status_id = decision["mutation_id"], decision["status_id"]
    require(mutation_id in deadlines, "reconciliation needs a recorded deadline")
    mutation, status = requests[mutation_id], replies[status_id]
    require(status_id > mutation_id and status["op"] == "status" and status["ok"],
            "reconciliation needs a subsequent successful status")
    require(status["result"]["state"] == "running", "reconciliation needs an active runtime")
    params = mutation["params"]
    peers = {peer["public_key"]: peer["address"] for peer in status["result"]["peers"]}
    if mutation["op"] == "peer_add":
        peer = params["peer"]
        desired_state_observed = peers.get(peer["public_key"]) == peer["address"]
    else:
        require(mutation["op"] == "peer_remove", "reconciliation needs a peer mutation")
        desired_state_observed = params["public_key"] not in peers
    applied = replies[mutation_id]["ok"]
    require(decision["outcome"] == ("applied" if applied else "not_applied"),
            "decision disagrees with the late mutation reply")
    require(desired_state_observed == applied, "decision disagrees with status peers")
    require(status["revision"] == params["expected_revision"] + int(applied),
            "status revision disagrees with the mutation outcome")


def request_rejection(request, validator, instance, capabilities, revision, duplicate):
    """Check the specified precedence through revision validation."""
    if duplicate:
        return "duplicate_id"
    if (set(request) != {"id", "op", "instance_id", "params"}
            or not isinstance(request["params"], dict)
            or not isinstance(request["instance_id"], str)
            or re.fullmatch(r"[0-9a-f]{32}", request["instance_id"]) is None
            or request["op"] == "hello"):
        return "invalid_request"
    if request["instance_id"] != instance:
        return "wrong_instance"
    op = request["op"]
    if op not in OPERATIONS:
        return "unknown_operation"
    if op in PEER_OPERATIONS and "live_peers" not in capabilities:
        return "unsupported_capability"
    if not validator.is_valid(request):
        return "invalid_request"
    if (op == "start" and revision != 0) or (op in PEER_OPERATIONS and revision == 0):
        return "invalid_state"
    if op in PEER_OPERATIONS and request["params"]["expected_revision"] != revision:
        return "revision_conflict"
    return None


def peer_set(records):
    peers = {peer["public_key"]: peer["address"] for peer in records}
    require(len(peers) == len(records), "duplicate peer public key")
    require(len(set(peers.values())) == len(peers), "duplicate peer address")
    return peers


def check_session(case, validator):
    pending = []
    requests, replies = {}, {}
    deadlines = set()
    instance = None
    revision = 0
    high_id = 0
    capabilities = None
    applied_peers = {}
    in_flight = None
    queue_overflow = False
    input_closed = False
    terminal_failure = False
    for index, step in enumerate(case["steps"]):
        require(len(step) == 1, "each step needs one action")
        action, value = next(iter(step.items()))
        if queue_overflow:
            require(action == "receive" and value.get("code") == "queue_full",
                    "overflow must produce a terminal queue_full error")
        if action == "send":
            require(not input_closed, "request follows a closed session")
            pending.append(value)
            if len(pending) > 2:
                require(in_flight == pending[0]["id"], "overflow needs a held executing request")
                queue_overflow = True
            requests[value["id"]] = value
        elif action == "receive":
            validator.validate(value)
            check_counters(value)
            instance = instance or value["instance_id"]
            require(value["instance_id"] == instance, "helper response changed instance")
            if value.get("type") == "session_error":
                require(not terminal_failure, "response follows terminal failure")
                require(not input_closed or value["code"] == "shutdown_timeout",
                        "only shutdown_timeout may follow EOF")
                require((value["code"] == "queue_full") == queue_overflow,
                        "queue_full requires one executing, one queued and one excess request")
                input_closed = terminal_failure = True
                queue_overflow = False
                pending.clear()
                continue
            require(not input_closed and pending, "correlated response without open pending work")
            request = pending.pop(0)
            if in_flight == request["id"]:
                in_flight = None
            require((value["id"], value["op"]) == (request["id"], request["op"]),
                    "response does not match the oldest request")
            duplicate = request["id"] <= high_id
            high_id = max(high_id, request["id"])
            code = value.get("error", {}).get("code")
            if capabilities is None:
                require(validator.is_valid(request) and request["op"] == "hello",
                        "first correlated exchange must be valid bootstrap")
                common = {1}.intersection(request["params"]["versions"])
                require(value["ok"] == bool(common), "negotiation outcome disagrees with versions")
                if value["ok"]:
                    require(value["result"]["version"] == max(common), "selected the wrong version")
                    capabilities = value["result"]["capabilities"]
                else:
                    require(code == "unsupported_version", "missing version mismatch error")
            else:
                expected = request_rejection(request, validator, instance, capabilities, revision, duplicate)
                if expected:
                    require(code == expected, f"expected {expected}, got {code}")
                else:
                    require(code not in {"duplicate_id", "invalid_request", "wrong_instance",
                                         "unknown_operation", "unsupported_capability",
                                         "invalid_state", "revision_conflict", "unsupported_version"},
                            f"unexpected rejection: {code}")
            if value["ok"] and request["op"] == "start":
                applied_peers = peer_set(request["params"]["peers"])
                revision = 1
            if value["ok"] and request["op"] in PEER_OPERATIONS:
                params = request["params"]
                if request["op"] == "peer_add":
                    peer = params["peer"]
                    require(peer["public_key"] not in applied_peers
                            and peer["address"] not in applied_peers.values(),
                            "successful add would replace an active peer")
                    applied_peers[peer["public_key"]] = peer["address"]
                else:
                    require(params["public_key"] in applied_peers, "successful removal of unknown peer")
                    del applied_peers[params["public_key"]]
                revision += 1
            require(value["revision"] == revision, "revision did not track applied mutations")
            if value["ok"] and request["op"] == "status":
                state = "running" if revision else "idle"
                require(value["result"]["state"] == state, "status disagrees with runtime state")
                require(peer_set(value["result"]["peers"]) == applied_peers,
                        "status does not contain the complete applied peer set")
            if code in {"unsupported_version", "start_failed"}:
                input_closed = terminal_failure = True
            if value["ok"] and request["op"] == "stop":
                input_closed = True
            replies[value["id"]] = value
        elif action == "in_flight":
            require(not input_closed and len(pending) == 1 and pending[0]["id"] == value
                    and in_flight is None, "in_flight must hold the executing request")
            in_flight = value
        elif action == "deadline":
            require(pending and pending[0]["id"] == value, "deadline must name the outstanding request")
            deadlines.add(value)
        elif action == "decision":
            check_reconciliation(value, requests, replies, deadlines)
        elif action == "eof":
            require(value is True and not input_closed, "unexpected EOF step")
            input_closed = True
            pending.clear()
        elif action == "exit":
            require(index == len(case["steps"]) - 1, "exit must be last")
            require(input_closed and not pending, "exit without terminal action or with pending work")
            require((value != 0) == terminal_failure, "exit does not match terminal outcome")
        else:
            raise AssertionError(f"unknown session step {action}")
    require("exit" in case["steps"][-1], "missing exit step")


def main():
    schema = read_json(ROOT / "message.schema.json")
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    frames = fixture_cases("frames.json")
    shapes = fixture_cases("message-shapes.json")
    sessions = fixture_cases("sessions.json")
    for case in frames:
        actual = frame_outcome(case["parts"])
        require(actual == case["expect"], f"{case['id']}: expected {case['expect']}, got {actual}")
    for case in shapes:
        require(validator.is_valid(case["message"]) == case["valid"],
                f"{case['id']}: schema validation did not match expected outcome")
    for case in sessions:
        try:
            check_session(case, validator)
        except Exception as exc:
            raise AssertionError(f"{case['id']}: {exc}") from exc
    print(f"Verified schema, {len(frames)} frame cases, {len(shapes)} message shapes, "
          f"and {len(sessions)} session transcripts.")


if __name__ == "__main__":
    main()
