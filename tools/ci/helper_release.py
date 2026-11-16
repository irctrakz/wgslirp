"""Build and verify the Linux helper archives used by CI and GitHub Releases."""

import argparse
import gzip
import hashlib
import io
import json
import re
import struct
import tarfile
from pathlib import Path


ARCHES = {"amd64": 62, "arm64": 183}
CAPABILITIES = ["restricted_tcp", "live_peers"]
MAX_BINARY_BYTES = 32 * 1024 * 1024
MEMBERS = {"wgslirp-helper": 0o755, "LICENSE": 0o644, "SOURCE.json": 0o644}
LICENSE = Path(__file__).resolve().parents[2] / "LICENSE"


def metadata(binary, source, version, arch):
    if not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("expected a full Git commit SHA")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}", version):
        raise ValueError("invalid helper binary version")
    if (not 64 <= len(binary) <= MAX_BINARY_BYTES
            or binary[:6] != b"\x7fELF\x02\x01"
            or int.from_bytes(binary[18:20], "little") != ARCHES[arch]):
        raise ValueError(f"expected a Linux {arch} ELF64 executable")
    offset = struct.unpack_from("<Q", binary, 32)[0]
    entry_size, count = struct.unpack_from("<HH", binary, 54)
    if (offset < 64 or entry_size < 56 or count == 0 or offset + entry_size * count > len(binary)
            or any(struct.unpack_from("<I", binary, offset + index * entry_size)[0] == 3
                   for index in range(count))):
        raise ValueError("helper requires valid ELF program headers and static linking")
    return {
        "source_commit": source,
        "binary_version": version,
        "platform": f"linux/{arch}",
        "protocol_versions": [1],
        "capabilities": CAPABILITIES,
        "binary_sha256": hashlib.sha256(binary).hexdigest(),
    }


def accepted_metadata(binary, source, version, arch, evidence_dir):
    expected = metadata(binary, source, version, arch)
    observed = json.loads((evidence_dir / f"acceptance-{arch}.json").read_bytes())
    if observed != expected:
        raise ValueError(f"binary and native acceptance evidence differ: linux/{arch}")
    return observed


def package(binary_path, output, source, version, arch, evidence_dir):
    binary = binary_path.read_bytes()
    contents = {
        "wgslirp-helper": binary,
        "LICENSE": LICENSE.read_bytes(),
        "SOURCE.json": (json.dumps(accepted_metadata(binary, source, version, arch, evidence_dir), indent=2) + "\n").encode(),
    }
    output.mkdir(parents=True, exist_ok=True)
    path = output / f"wgslirp-helper-{version}-linux-{arch}.tar.gz"
    with path.open("wb") as file, gzip.GzipFile(filename="", fileobj=file, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            for name, data in contents.items():
                member = tarfile.TarInfo(name)
                member.mode = MEMBERS[name]
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
    path.with_name(path.name + ".sha256").write_bytes(checksum(path))


def checksum(path):
    return f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n".encode()


def verify(directory, source, version, evidence_dir):
    expected = {f"wgslirp-helper-{version}-linux-{arch}.tar.gz": arch for arch in ARCHES}
    names = {path.name for path in directory.iterdir() if path.is_file()}
    if names != set(expected) | {f"{name}.sha256" for name in expected}:
        raise ValueError("unexpected helper artifact set")
    for name, arch in expected.items():
        path = directory / name
        if (directory / (name + ".sha256")).read_bytes() != checksum(path):
            raise ValueError(f"archive checksum mismatch: {name}")
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            if (len(members) != len(MEMBERS) or {member.name for member in members} != MEMBERS.keys()
                    or any(not member.isfile() or member.size > MAX_BINARY_BYTES
                           or member.mode != MEMBERS[member.name] for member in members)):
                raise ValueError(f"invalid archive members: {name}")
            binary = archive.extractfile("wgslirp-helper").read()
            actual = json.load(archive.extractfile("SOURCE.json"))
            if archive.extractfile("LICENSE").read() != LICENSE.read_bytes():
                raise ValueError(f"invalid license: {name}")
            if actual != accepted_metadata(binary, source, version, arch, evidence_dir):
                raise ValueError(f"invalid helper metadata: {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--source", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--arch", choices=ARCHES)
    args = parser.parse_args()
    if bool(args.binary) != bool(args.arch):
        parser.error("--binary and --arch are required together")
    try:
        if args.binary:
            package(args.binary, args.directory, args.source, args.version, args.arch, args.evidence)
        else:
            verify(args.directory, args.source, args.version, args.evidence)
    except (OSError, ValueError, tarfile.TarError) as err:
        parser.exit(1, f"{err}\n")


if __name__ == "__main__":
    main()
