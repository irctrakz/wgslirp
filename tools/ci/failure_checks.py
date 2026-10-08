"""Prove specific regression tests reject compilable defects in disposable copies."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile


CHECKS = {
    "retransmission": {
        "file": "pkg/socket/tcp_recovery.go",
        "before": "packet = b.buildTCPFlowLocked(f, seg.seq, 0x18, seg.data, nil, tos, ttl)",
        "after": "_ = tos; _ = ttl; packet = nil // injected: suppress RTO retransmission",
        "test": "TestTCPBridge_RTO",
        "diagnostic": "expected retransmission for seq",
    },
    "reservation-release": {
        "file": "pkg/socket/resource_budget.go",
        "before": "once.Do(func() { b.release(charge) })",
        "after": "once.Do(func() { /* injected: lose the reservation release */ })",
        "test": "TestPacketReservationsAreSharedFiniteAndReleaseOnce",
        "diagnostic": "budget used=296 want=0",
    },
    "fragment-recovery": {
        "file": "pkg/socket/ipv4_fragments.go",
        "before": "r.sources[d.key.src]--",
        "after": "// injected: retain per-source quota after owner release",
        "test": "TestIPv4FragmentSourceQuotaRecoversAfterExpiry",
        "diagnostic": "source quota did not recover after expiry",
    },
    "dial-cancellation": {
        "file": "pkg/socket/tcp_connect.go",
        "before": "case <-dialCtx.Done():\n\t\t\tif conn != nil {\n\t\t\t\tconn.Close()\n\t\t\t}",
        "after": "case <-dialCtx.Done():\n\t\t\t// injected: leak a successful late dial result",
        "test": "TestDialHandoffClosesLateSocketAfterCancellation",
        "diagnostic": "late socket not closed",
    },
}


def run(command, cwd, log, deadline=180):
    # Linux CI also has an independent container deadline. Kill the whole
    # command group here so a supervisor timeout cannot leave a test binary.
    with log.open("w", encoding="utf-8") as output:
        process = subprocess.Popen(command, cwd=cwd, stdout=output,
                                   stderr=subprocess.STDOUT,
                                   start_new_session=os.name == "posix")
        try:
            return process.wait(timeout=deadline)
        except subprocess.TimeoutExpired:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            process.wait()
            raise RuntimeError("supervisor timeout is not an accepted test failure")


def verify_test(log, test, expected, diagnostic=None):
    events = []
    for line in log.read_text(encoding="utf-8").splitlines():
        if line.startswith("{"):
            events.append(json.loads(line))
    terminal = [e["Action"] for e in events if e.get("Test") == test
                and e["Action"] in ("pass", "fail", "skip")]
    package = [e["Action"] for e in events if "Test" not in e
               and e["Action"] in ("pass", "fail", "skip")]
    if terminal != [expected] or package != [expected]:
        raise RuntimeError(f"required test/package did not {expected}: {terminal}, {package}")
    if any(e["Action"] == "skip" or
           (e["Action"] == "fail" and "Test" in e and e["Test"].split("/")[0] != test)
           for e in events):
        raise RuntimeError("skipped or unrelated failing test")
    output = "".join(e.get("Output", "") for e in events)
    if "panic:" in output or "WARNING: DATA RACE" in output:
        raise RuntimeError("panic/race is not the expected assertion failure")
    if diagnostic:
        owned_output = "".join(e.get("Output", "") for e in events
                               if e.get("Test", "").split("/")[0] == test)
        if diagnostic not in owned_output:
            raise RuntimeError("expected assertion diagnostic absent")


def copy_tracked(source, destination):
    files = subprocess.check_output(["git", "ls-files", "-z"], cwd=source).decode().split("\0")
    for name in filter(None, files):
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise RuntimeError("unsafe tracked path")
        original = source / relative
        if original.is_symlink():
            raise RuntimeError("symlink in source inventory")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("check", choices=CHECKS)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--go", default="go")
    parser.add_argument("--race", action="store_true")
    parser.add_argument("--container", help="run Go via docker exec in an already bounded container")
    parser.add_argument("--workspace-root", type=Path, help="host directory mounted read-only at /copies")
    args = parser.parse_args()
    source = args.source.resolve()
    args.evidence.mkdir(parents=True, exist_ok=True)
    evidence = args.evidence.resolve()
    if args.container and not args.workspace_root:
        parser.error("--container requires --workspace-root")
    check = CHECKS[args.check]
    report = {"check": args.check, "race": args.race, "passed": False,
              "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source).decode().strip(),
              "test": check["test"], "expected_diagnostic": check["diagnostic"]}
    try:
        with tempfile.TemporaryDirectory(prefix="wgslirp-failure-check-", dir=args.workspace_root) as workspace:
            copy = Path(workspace)
            copy_tracked(source, copy)
            file = copy / check["file"]
            original = file.read_text(encoding="utf-8")
            if original.count(check["before"]) != 1:
                raise RuntimeError("mutation anchor changed or ambiguous; review the control")
            report["original_sha256"] = hashlib.sha256(file.read_bytes()).hexdigest()
            command = [args.go, "test", "-json", "-count=1", "-timeout=60s"]
            if args.container:
                command = ["docker", "exec", "--workdir", "/copies/" + copy.name,
                           args.container] + command
            if args.race:
                command.append("-race")
            test_command = command + ["-run=^" + check["test"] + "$", "./pkg/socket"]
            if run(test_command, copy, evidence / "baseline.jsonl") != 0:
                raise RuntimeError("unchanged baseline failed")
            verify_test(evidence / "baseline.jsonl", check["test"], "pass")
            file.write_text(original.replace(check["before"], check["after"]), encoding="utf-8")
            report["mutated_sha256"] = hashlib.sha256(file.read_bytes()).hexdigest()
            (evidence / "mutation.json").write_text(json.dumps(check, indent=2), encoding="utf-8")
            if run(command + ["-run=^$", "./pkg/socket"], copy, evidence / "compile.jsonl") != 0:
                raise RuntimeError("mutant did not compile")
            if run(test_command, copy, evidence / "mutant.jsonl") != 1:
                raise RuntimeError("mutant was not rejected with normal test failure")
            verify_test(evidence / "mutant.jsonl", check["test"], "fail", check["diagnostic"])
        report["disposable_source_removed"] = not copy.exists()
        if not report["disposable_source_removed"]:
            raise RuntimeError("source copy remains")
        report["passed"] = True
        print("FAILURE_CHECK_ACCEPTED " + args.check)
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        (evidence / "result.json").write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
