# Exercise actual workflow release commands without network publication.
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from unittest.mock import patch

WORKFLOW = Path(__file__).resolve().parents[2] / '.github/workflows/docker.yml'


def run_block(name):
    lines = WORKFLOW.read_text(encoding='utf-8').splitlines()
    start = lines.index('      - name: ' + name)
    start = lines.index('        run: |', start) + 1
    block = []
    for line in lines[start:]:
        if line and not line.startswith('          '):
            break
        block.append(line[10:])
    return '\n'.join(block) + '\n'


def python_block(name):
    return re.search(r"python3 - <<'PY'\n(.*?)\nPY", run_block(name), re.S)[1]


class BinaryPackageTests(unittest.TestCase):
    def test_version_tags(self):
        code = python_block('Validate the version tag and reviewed source')
        for tag in ['v1.2.3', 'v0.1.0', 'v1.2.3-rc.1']:
            with self.subTest(tag=tag), patch.dict(os.environ, VERSION_TAG=tag):
                exec(code, {})
        for tag in ['latest', 'v1', 'v1.2', 'v01.2.3', 'v1.2.3/extra', 'v1.2.3-']:
            with self.subTest(tag=tag), patch.dict(os.environ, VERSION_TAG=tag):
                with self.assertRaises(AssertionError):
                    exec(code, {})

    def test_elf_architecture_and_static_linking(self):
        code = python_block('Package the tested executable')
        original = Path.cwd()
        cases = [('amd64', 62, 1, True), ('arm64', 183, 1, True),
                 ('amd64', 183, 1, False), ('arm64', 62, 1, False), ('amd64', 62, 3, False)]
        for arch, machine, header_type, accepted in cases:
            with self.subTest(arch=arch, machine=machine, header=header_type):
                with tempfile.TemporaryDirectory(prefix='wgslirp-binary-test-') as directory:
                    try:
                        os.chdir(directory)
                        Path('binary-package').mkdir()
                        binary = bytearray(120)
                        binary[:6] = b'\x7fELF\x02\x01'
                        struct.pack_into('<H', binary, 18, machine)
                        struct.pack_into('<Q', binary, 32, 64)
                        struct.pack_into('<HH', binary, 54, 56, 1)
                        struct.pack_into('<I', binary, 64, header_type)
                        Path('binary-package/wgslirp').write_bytes(binary)
                        with patch.dict(os.environ, RELEASE_ARCH=arch, GITHUB_SHA='abc',
                                        WGSLIRP_RELEASE_IMAGE='test@sha256:abc'):
                            if accepted:
                                exec(code, {})
                                metadata = json.loads(Path('binary-package/SOURCE.json').read_text())
                                self.assertEqual(metadata['platform'], 'linux/' + arch)
                            else:
                                with self.assertRaises(AssertionError):
                                    exec(code, {})
                    finally:
                        os.chdir(original)


    def test_windows_pe_architecture(self):
        code = re.search(r"@'\n(.*?)\n'@ \| python", run_block('Package the tested Windows executable'), re.S)[1]
        original = Path.cwd()
        for machine, accepted in [(0x8664, True), (0xAA64, False), (0x14C, False)]:
            with self.subTest(machine=machine), tempfile.TemporaryDirectory(prefix='wgslirp-pe-test-') as directory:
                try:
                    os.chdir(directory)
                    Path('binary-package').mkdir()
                    binary = bytearray(72)
                    binary[:2] = b'MZ'
                    struct.pack_into('<I', binary, 60, 64)
                    binary[64:68] = b'PE\0\0'
                    struct.pack_into('<H', binary, 68, machine)
                    Path('binary-package/wgslirp.exe').write_bytes(binary)
                    with patch.dict(os.environ, GITHUB_SHA='abc'):
                        if accepted:
                            exec(code, {})
                        else:
                            with self.assertRaises(AssertionError):
                                exec(code, {})
                finally:
                    os.chdir(original)

    def test_archive_metadata_and_content(self):
        code = python_block('Verify binary archives before publication')
        original = Path.cwd()
        for fault in [None, 'platform', 'source_commit', 'image', 'binary_sha256', 'extra_member',
                      'windows_platform', 'windows_source_commit', 'windows_binary_sha256', 'windows_extra_member']:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix='wgslirp-archive-test-') as directory:
                try:
                    os.chdir(directory)
                    for arch in ['amd64', 'arm64']:
                        metadata = {'platform': 'linux/' + arch, 'source_commit': 'abc',
                                    'image': 'test@sha256:abc', 'binary_sha256': hashlib.sha256(b'binary').hexdigest()}
                        if fault in metadata and arch == 'arm64':
                            metadata[fault] = 'incorrect'
                        contents = {'wgslirp': b'binary', 'LICENSE': b'license',
                                    'SOURCE.json': json.dumps(metadata).encode()}
                        if fault == 'extra_member' and arch == 'arm64':
                            contents['unexpected'] = b'bad'
                        with tarfile.open(f'wgslirp-abc-linux-{arch}.tar.gz', 'w:gz') as package:
                            for name, data in contents.items():
                                member = tarfile.TarInfo(name)
                                member.size = len(data)
                                package.addfile(member, io.BytesIO(data))
                    metadata = {'platform': 'windows/amd64', 'source_commit': 'abc',
                                'binary_sha256': hashlib.sha256(b'binary').hexdigest()}
                    if fault and fault.startswith('windows_') and fault[8:] in metadata:
                        metadata[fault[8:]] = 'incorrect'
                    with zipfile.ZipFile('wgslirp-abc-windows-amd64.zip', 'w') as package:
                        package.writestr('wgslirp.exe', b'binary')
                        package.writestr('LICENSE', b'license')
                        package.writestr('SOURCE.json', json.dumps(metadata))
                        if fault == 'windows_extra_member':
                            package.writestr('unexpected', b'bad')
                    with patch.dict(os.environ, GITHUB_SHA='abc', TESTED_IMAGE='test@sha256:abc'):
                        if fault is None:
                            exec(code, {})
                        else:
                            with self.assertRaises(AssertionError):
                                exec(code, {})
                finally:
                    os.chdir(original)


class ReleasePublicationTests(unittest.TestCase):
    def run_release(self, state='absent', upload_exit=0, tag='v1.2.3'):
        bash = shutil.which('bash')
        if not bash and os.name == 'nt':
            candidate = Path('C:/Program Files/Git/bin/bash.exe')
            if candidate.exists():
                bash = str(candidate)
        if not bash:
            self.skipTest('bash is required for workflow command controls')
        stub = r'''
gh() {
  printf '%s\n' "$*" >> calls.txt
  case "$2" in
    view)
      if [ "$RELEASE_STATE" = absent ]; then return 1; fi
      if [ "$RELEASE_STATE" = published ]; then printf '{"isDraft":false}';
      else printf '{"isDraft":true}'; fi ;;
    create) return 0 ;;
    upload) return "$UPLOAD_EXIT" ;;
    edit) return 0 ;;
    *) return 99 ;;
  esac
}
python3() { "$TEST_PYTHON" "$@"; }
'''
        with tempfile.TemporaryDirectory(prefix='wgslirp-release-control-') as directory:
            path = Path(directory)
            (path / 'binary-dist').mkdir()
            for filename in ['amd64.tar.gz', 'arm64.tar.gz', 'windows.zip', 'SHA256SUMS']:
                (path / 'binary-dist' / filename).write_text('test-only')
            env = os.environ | {'RELEASE_STATE': state, 'UPLOAD_EXIT': str(upload_exit),
                                'VERSION_TAG': tag, 'GITHUB_SHA': 'abc',
                                'TESTED_IMAGE': 'test@sha256:abc',
                                'GITHUB_REPOSITORY': 'example/test-only',
                                'GITHUB_STEP_SUMMARY': 'summary.txt',
                                'TEST_PYTHON': sys.executable.replace('\\', '/')}
            result = subprocess.run([bash, '--noprofile', '--norc'],
                                    input=stub + run_block('Publish a complete versioned release'),
                                    text=True, capture_output=True, cwd=directory, env=env, timeout=15)
            calls = (path / 'calls.txt').read_text().splitlines()
            return result.returncode, calls

    def test_new_release_stays_draft_until_upload_succeeds(self):
        result, calls = self.run_release()
        self.assertEqual(result, 0)
        self.assertEqual([line.split()[1] for line in calls], ['view', 'create', 'upload', 'edit'])
        self.assertIn('--draft', calls[1])
        self.assertIn('--verify-tag', calls[1])
        self.assertIn('--prerelease=false', calls[-1])

    def test_upload_failure_never_publishes(self):
        result, calls = self.run_release(upload_exit=1)
        self.assertNotEqual(result, 0)
        self.assertFalse(any(line.startswith('release edit ') for line in calls))

    def test_published_version_is_never_overwritten(self):
        result, calls = self.run_release(state='published')
        self.assertNotEqual(result, 0)
        self.assertEqual(len(calls), 1)

    def test_incomplete_draft_can_be_resumed(self):
        result, calls = self.run_release(state='draft')
        self.assertEqual(result, 0)
        self.assertEqual([line.split()[1] for line in calls], ['view', 'upload', 'edit'])

    def test_suffix_tag_creates_prerelease(self):
        result, calls = self.run_release(tag='v1.2.3-rc.1')
        self.assertEqual(result, 0)
        self.assertIn('--prerelease=true', calls[-1])


if __name__ == '__main__':
    unittest.main()
