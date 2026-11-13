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
# Public test vector from RFC 7748 section 6.1, encoded as WireGuard keys.
FIXTURE_PUBLIC_KEYS = {
    "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=":
        "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=",
}
ZERO_KEY = "A" * 43 + "="


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
    if not raw:
        return "clean_eof"
    terminated = raw.endswith(b"\n")
    payload = raw[:-1].removesuffix(b"\r") if terminated else raw
    if len(payload) > MAX_FRAME_BYTES:
        return "frame_too_large"
    if not terminated or b"\n" in payload:
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


def check_reconciliation(decision, requests, replies):
    mutation_id, status_id = decision["mutation_id"], decision["status_id"]
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
    reply = replies[mutation_id]
    applied = reply["ok"]
    require(decision["outcome"] == ("applied" if applied else "not_applied"),
            "decision disagrees with the late mutation reply")
    require(decision["desired_state_holds"] is desired_state_observed,
            "decision disagrees with status peers")
    require(not applied or desired_state_observed, "successful mutation is missing from status")
    require(status["revision"] == reply["revision"],
            "status revision disagrees with the mutation reply")


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


def invalid_address(address, *, allow_loopback=False):
    # The schema has already validated the dotted-decimal IPv4 shape.
    first_octet = int(address.split(".", 1)[0])
    return first_octet == 0 or first_octet >= 224 or (first_octet == 127 and not allow_loopback)


def invalid_peer(peer, service_addresses, server_key):
    return (peer["public_key"] in {ZERO_KEY, server_key}
            or invalid_address(peer["address"])
            or peer["address"] in service_addresses)


def invalid_config(config):
    if config["private_key"] == ZERO_KEY:
        return True
    mappings = {(mapping["guest_ip"], mapping["guest_port"]) for mapping in config["mappings"]}
    if len(mappings) != len(config["mappings"]):
        return True
    if any(invalid_address(mapping["guest_ip"])
           or invalid_address(mapping["host_ip"], allow_loopback=True)
           for mapping in config["mappings"]):
        return True
    service_addresses = {address for address, _ in mappings}
    server_key = FIXTURE_PUBLIC_KEYS.get(config["private_key"])
    peers = config["peers"]
    return (len({peer["public_key"] for peer in peers}) != len(peers)
            or len({peer["address"] for peer in peers}) != len(peers)
            or any(invalid_peer(peer, service_addresses, server_key) for peer in peers))


def check_session(case, validator):
    pending = []
    requests, replies = {}, {}
    unresolved_mutation = None
    reconciliation_status = None
    reconciliation_failed = False
    control_timed_out = False
    exited = False
    reaped = False
    instance = None
    revision = 0
    high_id = 0
    capabilities = None
    applied_peers = {}
    assigned_addresses = set()
    service_addresses = set()
    startup_identity = None
    in_flight = None
    terminal_code = None
    terminal_response_sent = False
    stdout_failed = False
    requests_closed = False
    stdin_closed_by_controller = False
    shutdown_grace_expired = False
    forced_termination = False
    terminal_failure = False
    for index, step in enumerate(case["steps"]):
        require(len(step) == 1, "each step needs one action")
        action, value = next(iter(step.items()))
        require(not exited or action in {"eof", "reap", "replace_helper"}, "action after helper exit")
        if action == "send":
            require(not requests_closed, "request follows a closed session")
            require(not reconciliation_failed, "failed reconciliation requires shutdown")
            require(not control_timed_out, "control timeout requires shutdown")
            if unresolved_mutation is not None:
                require(value["op"] == "status" and reconciliation_status is None
                        and value["id"] > unresolved_mutation,
                        "reconcile the timed-out mutation before sending another request")
                reconciliation_status = value["id"]
            pending.append(value)
            if len(pending) > 2:
                require(in_flight == pending[0]["id"], "overflow needs a held executing request")
                terminal_code = "queue_full"
                requests_closed = terminal_failure = True
                pending.clear()
            requests[value["id"]] = value
        elif action == "receive":
            require(not stdout_failed and not terminal_response_sent,
                    "response after terminal output closed")
            validator.validate(value)
            check_counters(value)
            instance = instance or value["instance_id"]
            require(value["instance_id"] == instance, "helper response changed instance")
            if value.get("type") == "session_error":
                if terminal_code:
                    require(value["code"] == terminal_code, f"expected terminal {terminal_code}")
                else:
                    require(not requests_closed or value["code"] == "shutdown_timeout",
                            "only shutdown_timeout may follow EOF")
                    require(value["code"] != "queue_full", "queue_full requires an overflow")
                requests_closed = terminal_failure = True
                terminal_response_sent = True
                pending.clear()
                continue
            require(not requests_closed and pending, "correlated response without open pending work")
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
                if (expected is None and request["op"] in {"start", "validate"}
                        and invalid_config(request["params"])):
                    expected = "invalid_config"
                if expected is None and request["op"] == "peer_add":
                    peer = request["params"]["peer"]
                    if invalid_peer(peer, service_addresses, startup_identity[1]):
                        expected = "invalid_config"
                    elif (peer["address"] in assigned_addresses
                          or peer["public_key"] in applied_peers):
                        expected = "peer_conflict"
                    elif len(applied_peers) >= 128 or len(assigned_addresses) >= 1024:
                        expected = "peer_limit"
                if expected is None and request["op"] == "peer_remove":
                    key = request["params"]["public_key"]
                    if key == ZERO_KEY:
                        expected = "invalid_config"
                    elif key not in applied_peers:
                        expected = "peer_not_found"
                if code == "peer_not_found":
                    require(request["op"] == "peer_remove", "peer_not_found is only valid for removal")
                if code in {"peer_conflict", "peer_limit"}:
                    require(request["op"] == "peer_add", f"{code} is only valid for addition")
                if expected:
                    require(code == expected, f"expected {expected}, got {code}")
                else:
                    require(code not in {"duplicate_id", "invalid_request", "wrong_instance",
                                         "unknown_operation", "unsupported_capability",
                                         "invalid_state", "revision_conflict", "unsupported_version",
                                         "peer_not_found", "peer_conflict", "peer_limit"},
                            f"unexpected rejection: {code}")
            if value["ok"] and request["op"] == "start":
                config = request["params"]
                applied_peers = peer_set(config["peers"])
                assigned_addresses = set(applied_peers.values())
                service_addresses = {mapping["guest_ip"] for mapping in config["mappings"]}
                startup_identity = (value["result"]["listen_port"], value["result"]["server_public_key"])
                requested_port = config.get("listen_port", 51820)
                require(requested_port in {0, startup_identity[0]}, "start did not bind the configured port")
                expected_key = FIXTURE_PUBLIC_KEYS.get(config["private_key"])
                require(expected_key is not None, "missing known public key for startup fixture")
                require(startup_identity[1] == expected_key, "start public key disagrees with private key")
                revision = 1
            if value["ok"] and request["op"] in PEER_OPERATIONS:
                params = request["params"]
                if request["op"] == "peer_add":
                    peer = params["peer"]
                    applied_peers[peer["public_key"]] = peer["address"]
                    assigned_addresses.add(peer["address"])
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
                if state == "running":
                    identity = (value["result"]["listen_port"], value["result"]["server_public_key"])
                    require(identity == startup_identity, "status identity disagrees with start")
            if code in {"unsupported_version", "start_failed"}:
                requests_closed = terminal_failure = True
                terminal_response_sent = True
                pending.clear()
            if value["ok"] and request["op"] == "stop":
                requests_closed = True
                terminal_response_sent = True
                pending.clear()
            replies[value["id"]] = value
            if value["id"] == reconciliation_status and not value["ok"]:
                reconciliation_failed = True
        elif action == "in_flight":
            require(not requests_closed and len(pending) == 1 and pending[0]["id"] == value
                    and in_flight is None, "in_flight must hold the executing request")
            in_flight = value
        elif action == "deadline":
            require(not control_timed_out, "control deadline already expired")
            require(any(request["id"] == value for request in pending),
                    "deadline must name an outstanding request")
            if value == reconciliation_status:
                require(not reconciliation_failed, "reconciliation already failed")
                reconciliation_failed = True
            elif requests[value]["op"] in PEER_OPERATIONS:
                require(unresolved_mutation is None and pending[0]["id"] == value,
                        "mutation deadline must name the executing peer operation")
                unresolved_mutation = value
            else:
                require(unresolved_mutation is None, "unexpected deadline during reconciliation")
                control_timed_out = True
        elif action == "decision":
            require(not requests_closed and not reconciliation_failed
                    and unresolved_mutation is not None and reconciliation_status is not None
                    and value["mutation_id"] == unresolved_mutation
                    and value["status_id"] == reconciliation_status,
                    "decision must resolve the pending mutation using its reconciliation status")
            require(unresolved_mutation in replies and reconciliation_status in replies,
                    "reconciliation decision requires both replies")
            check_reconciliation(value, requests, replies)
            unresolved_mutation = reconciliation_status = None
        elif action == "eof":
            require(value is True and not stdin_closed_by_controller,
                    "controller may close stdin only once")
            stdin_closed_by_controller = requests_closed = True
            pending.clear()
        elif action == "stdout_failed":
            require(isinstance(value, str) and "\n" not in value and not stdout_failed
                    and not terminal_response_sent,
                    "stdout failure must give an unterminated prefix or an empty string")
            stdout_failed = requests_closed = terminal_failure = True
            pending.clear()
        elif action == "cleanup_timeout":
            require(value is True and requests_closed and not terminal_response_sent
                    and terminal_code != "shutdown_timeout", "unexpected cleanup timeout")
            terminal_code = "shutdown_timeout"
            terminal_failure = True
        elif action == "shutdown_grace_expired":
            require(value is True and stdin_closed_by_controller and not shutdown_grace_expired,
                    "shutdown grace period requires closing stdin")
            shutdown_grace_expired = True
        elif action == "force_terminate":
            require(value is True and shutdown_grace_expired and not forced_termination,
                    "forced termination requires closing stdin and waiting for exit")
            forced_termination = stdout_failed = terminal_failure = True
        elif action == "unexpected_exit":
            require(type(value) is int and not terminal_response_sent and not forced_termination,
                    "unexpected exit must precede any terminal response or forced termination")
            requests_closed = terminal_failure = exited = True
            pending.clear()
        elif action == "exit":
            require(requests_closed and not pending, "exit without terminal action or with pending work")
            require(type(value) is int, "exit status must be an integer")
            require((value != 0) == terminal_failure, "exit does not match terminal outcome")
            exited = True
        elif action == "reap":
            require(value is True and exited and not reaped, "reaping requires one observed exit")
            reaped = True
        elif action == "replace_helper":
            recovery_failed = (control_timed_out or reconciliation_failed
                               or (unresolved_mutation is not None and terminal_failure))
            require(value is True and recovery_failed and requests_closed and reaped
                    and index == len(case["steps"]) - 1,
                    "replacement after failed recovery requires closing and reaping the helper")
            require(stdin_closed_by_controller, "replacement requires closing controller stdin")
        else:
            raise AssertionError(f"unknown session step {action}")
    require(exited, "missing exit step")


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
