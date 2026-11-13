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


def check_session(case, validator):
    pending = []
    requests, replies = {}, {}
    deadlines = set()
    instance = None
    revision = 0
    high_id = 0
    capabilities = None
    input_closed = False
    terminal_failure = False
    for index, step in enumerate(case["steps"]):
        require(len(step) == 1, "each step needs one action")
        action, value = next(iter(step.items()))
        if action == "send":
            require(not input_closed, "request follows a closed session")
            pending.append(value)
            require(len(pending) <= 2, "more than one executing and one queued request")
            requests[value["id"]] = value
        elif action == "receive":
            validator.validate(value)
            check_counters(value)
            instance = instance or value["instance_id"]
            require(value["instance_id"] == instance, "helper response changed instance")
            if value.get("type") == "session_error":
                input_closed = terminal_failure = True
                pending.clear()
                continue
            request = pending.pop(0)
            require((value["id"], value["op"]) == (request["id"], request["op"]),
                    "response does not match the oldest request")
            duplicate = request["id"] <= high_id
            high_id = max(high_id, request["id"])
            code = value.get("error", {}).get("code")
            require((code == "duplicate_id") == duplicate, "duplicate ID outcome is inconsistent")
            shape_error = code in {"unknown_operation", "invalid_request"}
            require(validator.is_valid(request) != shape_error, "request shape does not match outcome")
            if code == "wrong_instance":
                require(request["instance_id"] != instance, "wrong_instance needs a mismatched instance")
            elif request["op"] != "hello":
                require(request["instance_id"] == instance, "request instance does not match response")
            if request["op"] == "hello":
                common = {1}.intersection(request["params"]["versions"])
                require(value["ok"] == bool(common), "negotiation outcome disagrees with versions")
                if value["ok"]:
                    require(value["result"]["version"] == max(common), "selected the wrong version")
                    capabilities = value["result"]["capabilities"]
                else:
                    require(code == "unsupported_version", "missing version mismatch error")
            else:
                require(capabilities is not None, "operation before negotiation")
            if request["op"] in {"peer_add", "peer_remove"}:
                require((code == "unsupported_capability") == ("live_peers" not in capabilities),
                        "peer operation outcome disagrees with capabilities")
                if value["ok"] or code == "revision_conflict":
                    matches = request["params"]["expected_revision"] == revision
                    require(value["ok"] == matches, "peer operation outcome disagrees with revision")
            if value["ok"] and request["op"] in {"start", "peer_add", "peer_remove"}:
                revision += 1
            require(value["revision"] == revision, "revision did not track applied mutations")
            if value["ok"] and request["op"] == "status":
                state = "running" if revision else "idle"
                require(value["result"]["state"] == state, "status disagrees with runtime state")
            if code in {"unsupported_version", "start_failed"}:
                input_closed = terminal_failure = True
            if value["ok"] and request["op"] == "stop":
                input_closed = True
            replies[value["id"]] = value
        elif action == "deadline":
            require(pending and pending[0]["id"] == value, "deadline must name the outstanding request")
            deadlines.add(value)
        elif action == "decision":
            check_reconciliation(value, requests, replies, deadlines)
        elif action == "eof":
            require(value is True, "eof must be true")
            input_closed = True
            pending.clear()
        elif action == "exit":
            require(index == len(case["steps"]) - 1, "exit must be last")
            require(input_closed and not pending, "exit without terminal action or with pending work")
            require(value == int(terminal_failure), "exit does not match terminal outcome")
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
