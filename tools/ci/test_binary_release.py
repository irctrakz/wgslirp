# Exercise actual workflow release commands without network publication.
import fnmatch
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

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/docker.yml'
HELPER_WORKFLOW = WORKFLOW.with_name('helper-release.yml')
GO_WORKFLOW = WORKFLOW.with_name('go.yml')
GO_SHARED_PACKAGES = ROOT / 'tools/ci/go-shared-packages.txt'
PUBLISHER = ROOT / 'tools/ci/publish-binary-release.sh'
SOURCE_VALIDATION = ROOT / 'tools/ci/validate-release-source.sh'


def checksum_sidecar(path):
    return f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n'.encode()


def run_block(name, workflow=WORKFLOW):
    lines = workflow.read_text(encoding='utf-8').splitlines()
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


def workflow_bash(test):
    bash = shutil.which('bash')
    if not bash and os.name == 'nt':
        candidate = Path('C:/Program Files/Git/bin/bash.exe')
        if candidate.exists():
            bash = str(candidate)
    if not bash:
        test.skipTest('bash is required for workflow command controls')
    return bash


def assert_partial_rerun_artifacts(test, path, job, expected):
    workflow = path.read_text(encoding='utf-8')
    release = workflow.split(f'\n  {job}:\n', 1)[1].split('\n  docker:', 1)[0]
    patterns = re.findall(r"pattern: '([^']+)'", release)
    # An ARM64 retry must replace its own artifacts and keep prior successes.
    templates = re.findall(r"name: '((?:helper-(?:binaries|acceptance)|binaries)-[^']+)'\n\s+overwrite: true", workflow)
    test.assertEqual(len(templates), 2)
    available = {}
    for template in templates:
        for arch in (('amd64', 'arm64') if 'matrix.arch' in template else ('amd64',)):
            name = template.replace('${{ matrix.arch }}', arch)
            available[name.replace('${{ github.run_attempt }}', '1')] = 1
            if arch == 'arm64':
                available[name.replace('${{ github.run_attempt }}', '2')] = 2
    selected = {name: attempt for name, attempt in available.items()
                if any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)}
    test.assertEqual(selected, {name: 2 if name.endswith('-arm64') else 1 for name in expected})


class BinaryPackageTests(unittest.TestCase):
    def test_partial_rerun_reuses_standalone_artifacts(self):
        assert_partial_rerun_artifacts(self, WORKFLOW, 'release-binaries',
                                       {'binaries-amd64', 'binaries-arm64', 'binaries-windows-amd64'})

    def test_standalone_verification_rejects_misdirected_sidecar(self):
        bash = workflow_bash(self)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dist = root / 'binary-dist'
            dist.mkdir()
            standalone = ['wgslirp-abc-linux-amd64.tar.gz', 'wgslirp-abc-linux-arm64.tar.gz',
                          'wgslirp-abc-windows-amd64.zip']
            for name in standalone:
                path = dist / name
                path.write_bytes(name.encode())
                path.with_name(name + '.sha256').write_bytes(checksum_sidecar(path))
            env = os.environ | {'GITHUB_SHA': 'abc', 'VERSION_TAG': 'v1.2.3'}
            # Archive content and metadata are exercised by the next tests.
            verify = 'python3() { cat > /dev/null; }\n' + run_block('Verify binary archives before publication')
            good = subprocess.run([bash], input=verify, text=True, capture_output=True, cwd=root, env=env)
            self.assertEqual(good.returncode, 0, good.stderr)
            wrong = dist / (standalone[1] + '.sha256')
            wrong.write_bytes(checksum_sidecar(dist / standalone[0]))
            bad = subprocess.run([bash], input=verify, text=True, capture_output=True, cwd=root, env=env)
            self.assertNotEqual(bad.returncode, 0)

    def test_version_tags_and_reviewed_source(self):
        bash = workflow_bash(self)
        stub = """git() {
          case "$1" in
            fetch) return 0 ;;
            rev-parse) echo false ;;
            merge-base)
              echo checked-source
              [[ "$*" == 'merge-base --is-ancestor abc refs/remotes/origin/master' && "$REVIEWED" == yes ]]
              ;;
            *) return 99 ;;
          esac
        }
        """
        script = stub + SOURCE_VALIDATION.read_text(encoding='utf-8')
        for prefix, other in [('v', 'helper-v'), ('helper-v', 'v')]:
            valid = [prefix + suffix for suffix in ('1.2.3', '0.1.0', '1.2.3-rc.1')]
            invalid = [other + '1.2.3', 'latest'] + [
                prefix + suffix for suffix in ('1', '1.2', '01.2.3', '1.2.3/extra', '1.2.3-')]
            for tag, reviewed, accepted in ([(tag, 'yes', True) for tag in valid]
                                            + [(tag, 'yes', False) for tag in invalid]
                                            + [(valid[0], 'no', False)]):
                with self.subTest(prefix=prefix, tag=tag, reviewed=reviewed):
                    env = os.environ | {'GITHUB_REF_NAME': tag, 'GITHUB_SHA': 'abc', 'REVIEWED': reviewed}
                    result = subprocess.run([bash, '-s', '--', prefix], input=script, env=env,
                                            text=True, capture_output=True)
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)
                    self.assertEqual('checked-source' in result.stdout, tag in valid)

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


class HelperPackageTests(unittest.TestCase):
    def test_helper_matrix_rejects_missing_or_tampered_artifacts(self):
        import helper_release

        source = 'a' * 40
        version = 'v1.2.3'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dist = root / 'dist'
            evidence = root / 'evidence'
            evidence.mkdir()
            binary = root / 'wgslirp-helper'
            for arch, machine in helper_release.ARCHES.items():
                elf = bytearray(120)
                elf[:6] = b'\x7fELF\x02\x01'
                struct.pack_into('<H', elf, 18, machine)
                struct.pack_into('<Q', elf, 32, 64)
                struct.pack_into('<HH', elf, 54, 56, 1)
                struct.pack_into('<I', elf, 64, 1)
                binary.write_bytes(elf)
                accepted = helper_release.metadata(elf, source, version, arch)
                (evidence / f'acceptance-{arch}.json').write_text(json.dumps(accepted))
                helper_release.package(binary, dist, source, version, arch, evidence)
            helper_release.verify(dist, source, version, evidence)
            with self.assertRaisesRegex(ValueError, 'acceptance evidence'):
                helper_release.verify(dist, 'b' * 40, version, evidence)
            archive = dist / f'wgslirp-helper-{version}-linux-arm64.tar.gz'
            # Replace the binary and rebuild both checksum layers. The native
            # job's independent record must still reject the substitution.
            binary.write_bytes(binary.read_bytes() + b'different build')
            fake_evidence = root / 'fake'
            fake_evidence.mkdir()
            substitute = helper_release.metadata(binary.read_bytes(), source, version, 'arm64')
            (fake_evidence / 'acceptance-arm64.json').write_text(json.dumps(substitute))
            with self.assertRaisesRegex(ValueError, 'acceptance evidence'):
                helper_release.package(binary, dist, source, version, 'arm64', evidence)
            helper_release.package(binary, dist, source, version, 'arm64', fake_evidence)
            with self.assertRaisesRegex(ValueError, 'acceptance evidence'):
                helper_release.verify(dist, source, version, evidence)
            with archive.open('ab') as file:
                file.write(b'tampered')
            with self.assertRaisesRegex(ValueError, 'checksum'):
                helper_release.verify(dist, source, version, evidence)
            archive.unlink()
            with self.assertRaisesRegex(ValueError, 'artifact set'):
                helper_release.verify(dist, source, version, evidence)

    def test_partial_rerun_reuses_helper_artifacts(self):
        assert_partial_rerun_artifacts(self, HELPER_WORKFLOW, 'release-helper',
                                       {'helper-binaries-amd64', 'helper-binaries-arm64',
                                        'helper-acceptance-amd64', 'helper-acceptance-arm64'})


class ReleasePublicationFixture(unittest.TestCase):
    def run_release(self, state='absent', upload_exit=0, tag='v1.2.3', inventory=None,
                    asset_fault=None, remote_tag='lightweight', replace_draft='', profile='standalone'):
        bash = workflow_bash(self)
        stub = r'''
git() {
  ref="refs/tags/$VERSION_TAG"
  [[ "$*" == *"ls-remote --exit-code origin $ref $ref^{}" ]] || return 99
  if [ "$REMOTE_TAG" = deleted ] || { [ "$REMOTE_TAG" = deleted-after-upload ] && [ -f uploaded ]; }; then
    return 2
  fi
  sha="$GITHUB_SHA"
  if [ "$REMOTE_TAG" = moved ] || { [ "$REMOTE_TAG" = moved-after-upload ] && [ -f uploaded ]; }; then
    sha=def
  fi
  if [ "$REMOTE_TAG" = annotated ]; then
    printf 'tag-object\t%s\n%s\t%s^{}\n' "$ref" "$sha" "$ref"
  else
    printf '%s\t%s\n' "$sha" "$ref"
  fi
}
gh() {
  local release_id=123
  if [ "$REPLACE_DRAFT" = create ] && [ -f created ]; then release_id=456; fi
  [ -f calls.txt ] || touch calls.txt
  if [ "$1" = api ]; then
    if [ "$2" = --method ]; then
      printf '%s\n' "$*" >> calls.txt
      case "$3" in
        POST)
          [[ "$4" == "repos/$GH_REPO/releases" ]] || return 99
          touch created
          printf '{"id":123,"tag_name":"%s","draft":true}\n' "$VERSION_TAG"
          return ;;
        DELETE)
          if [ "$REPLACE_DRAFT" = delete ]; then
            # ID 321 was on draft 123. Replacement draft 456 has asset 654.
            [[ "$4" == "repos/$GH_REPO/releases/assets/654" ]]
          else
            [[ "$4" == "repos/$GH_REPO/releases/assets/321" ]]
          fi
          return ;;
        PATCH)
          if [ "$REPLACE_DRAFT" = publish ]; then
            [[ "$4" == "repos/$GH_REPO/releases/456" ]]
          else
            [[ "$4" == "repos/$GH_REPO/releases/$release_id" ]]
          fi
          return ;;
      esac
    fi
    if [ "$2" = "repos/$GH_REPO/releases/$release_id" ]; then
      printf '{"id":%s,"tag_name":"%s","draft":true}\n' "$release_id" "$VERSION_TAG"
      return
    fi
    if [ "$REPLACE_DRAFT" = create ]; then printf 'inventory %s\n' "$*" >> calls.txt; fi
    [[ "$*" == *"repos/$GH_REPO/releases/$release_id/assets?per_page=100" ]] || return 99
    if [ -f uploaded ]; then cat uploaded-assets.json; else cat initial-assets.json; fi
    return
  fi
  printf '%s\n' "$*" >> calls.txt
  case "$2" in
    view)
      if [ "$RELEASE_STATE" = absent ] && [ ! -f created ]; then return 1;
      elif [ "$release_id" = 456 ]; then printf '{"draft":true,"id":456}\n';
      else cat initial.json; fi ;;
    upload)
      if [[ "$REPLACE_DRAFT" == delete || "$REPLACE_DRAFT" == upload ]]; then
        printf 'modified replacement 456\n' >> calls.txt
      fi
      return 99 ;;
    edit)
      if [ "$REPLACE_DRAFT" = publish ]; then printf 'published replacement 456\n' >> calls.txt; fi
      return 0 ;;
    *) return 99 ;;
  esac
}
curl() {
  local url="${!#}" auth release_id=123
  IFS= read -r auth
  [[ "$auth" == 'Authorization: Bearer test-token' ]] || return 99
  printf 'upload %s\n' "$url" >> calls.txt
  if [[ "$REPLACE_DRAFT" == create || "$REPLACE_DRAFT" == upload ]]; then
    release_id=456
  fi
  [[ "$url" == "https://uploads.github.com/repos/$GH_REPO/releases/$release_id/assets?name="* ]] || return 99
  if [ "$UPLOAD_EXIT" != 0 ]; then return "$UPLOAD_EXIT"; fi
  touch uploaded
}
python3() { "$TEST_PYTHON" "$@"; }
'''
        with tempfile.TemporaryDirectory(prefix='wgslirp-release-control-') as directory:
            path = Path(directory)
            if profile == 'helper':
                dist = path / 'helper-dist'
                version = tag.removeprefix('helper-')
                archives = [f'wgslirp-helper-{version}-linux-{arch}.tar.gz' for arch in ('amd64', 'arm64')]
            else:
                dist = path / 'binary-dist'
                archives = ['wgslirp-abc-linux-amd64.tar.gz', 'wgslirp-abc-linux-arm64.tar.gz',
                            'wgslirp-abc-windows-amd64.zip']
            dist.mkdir()
            manifest = b''
            for filename in archives:
                (dist / filename).write_bytes(filename.encode())
                sidecar = checksum_sidecar(dist / filename)
                (dist / (filename + '.sha256')).write_bytes(sidecar)
                manifest += sidecar
            names = archives + ['SHA256SUMS']
            initial = ['stale-helper.tar.gz'] if state == 'extra' else names[:1] if state == 'draft' else []
            (path / 'initial.json').write_text(json.dumps({'draft': state != 'published', 'id': 123}))
            (path / 'initial-assets.json').write_text(json.dumps([[{'name': name, 'id': 321} for name in initial]]))
            uploaded = []
            for name in (names if inventory is None else inventory):
                data = manifest if name == 'SHA256SUMS' else (dist / name).read_bytes()
                uploaded.append({'name': name, 'state': 'uploaded', 'size': len(data),
                                 'digest': 'sha256:' + hashlib.sha256(data).hexdigest()})
            if asset_fault:
                uploaded[-1].update(asset_fault)
            (path / 'uploaded-assets.json').write_text(json.dumps([uploaded[:1], uploaded[1:]]))
            env = os.environ | {'RELEASE_STATE': state, 'UPLOAD_EXIT': str(upload_exit),
                                'VERSION_TAG': tag, 'GITHUB_SHA': 'abc',
                                'REMOTE_TAG': remote_tag, 'GH_REPO': 'example/test-only',
                                'REPLACE_DRAFT': replace_draft, 'GH_TOKEN': 'test-token',
                                'GITHUB_REPOSITORY': 'example/test-only',
                                'GITHUB_STEP_SUMMARY': 'summary.txt',
                                'TEST_PYTHON': sys.executable.replace('\\', '/')}
            env.pop('TESTED_IMAGE', None)
            if profile == 'standalone':
                env['TESTED_IMAGE'] = 'test@sha256:abc'
            result = subprocess.run([bash, '--noprofile', '--norc', '-s', '--', profile],
                                    input=stub + PUBLISHER.read_text(encoding='utf-8'),
                                    text=True, capture_output=True, cwd=directory, env=env, timeout=15)
            log = path / 'calls.txt'
            calls = log.read_text().splitlines() if log.exists() else []
            if result.returncode == 0:
                self.assertEqual((dist / 'SHA256SUMS').read_bytes(), manifest)
                self.assertEqual([call.rsplit('=', 1)[1] for call in calls if call.startswith('upload ')], names)
            return result.returncode, calls

    @staticmethod
    def operations(calls):
        return [line.split()[2].lower() if line.startswith('api --method ') else
                line.split()[1] if line.startswith('release ') else line.split()[0] for line in calls]


class ReleasePublicationTests(ReleasePublicationFixture):
    def test_new_release_stays_draft_until_upload_succeeds(self):
        result, calls = self.run_release()
        self.assertEqual(result, 0)
        self.assertEqual(self.operations(calls), ['view', 'post'] + ['upload'] * 4 + ['patch'])
        self.assertTrue(calls[1].startswith('api --method POST repos/example/test-only/releases '))
        for field in ('-f tag_name=v1.2.3', '-f target_commitish=abc', '-f name=v1.2.3',
                      '-F draft=true', '-F prerelease=false', '-F body=@release-notes.txt'):
            self.assertIn(field, calls[1])
        self.assertIn('api --method PATCH repos/example/test-only/releases/123 ', calls[-1])
        for field in ('-f tag_name=v1.2.3', '-f target_commitish=abc', '-F draft=false',
                      '-F prerelease=false', '-f make_latest=false', '-F body=@release-notes.txt'):
            self.assertIn(field, calls[-1])

    def test_upload_failure_never_publishes(self):
        result, calls = self.run_release(upload_exit=1)
        self.assertNotEqual(result, 0)
        self.assertEqual(self.operations(calls), ['view', 'post', 'upload'])

    def test_replacement_immediately_after_creation_is_untouched(self):
        result, calls = self.run_release(replace_draft='create')
        self.assertNotEqual(result, 0)
        self.assertEqual(self.operations(calls), ['view', 'post', 'inventory'])
        self.assertIn('releases/123/assets?per_page=100', calls[-1])
        self.assertFalse(any('456' in call for call in calls))

    def test_published_version_is_never_overwritten(self):
        result, calls = self.run_release(state='published')
        self.assertNotEqual(result, 0)
        self.assertEqual(len(calls), 1)

    def test_incomplete_draft_can_be_resumed(self):
        result, calls = self.run_release(state='draft')
        self.assertEqual(result, 0)
        self.assertEqual(self.operations(calls), ['view', 'delete'] + ['upload'] * 4 + ['patch'])
        self.assertIn('api --method DELETE repos/example/test-only/releases/assets/321 ', calls[1])
        self.assertTrue(all('releases/123/assets?name=' in call for call in calls[2:-1]))

    def test_replaced_draft_is_never_published(self):
        result, calls = self.run_release(state='draft', replace_draft='publish')
        self.assertNotEqual(result, 0)
        self.assertEqual(self.operations(calls), ['view', 'delete'] + ['upload'] * 4 + ['patch'])
        self.assertTrue(calls[-1].startswith('api --method PATCH repos/example/test-only/releases/123 '))
        self.assertFalse(any('456' in call for call in calls))

    def test_replacement_before_upload_does_not_redirect_asset_mutations(self):
        for point, state, expected, target in (
                ('delete', 'draft', ['view', 'delete'], 'releases/assets/321'),
                ('upload', 'absent', ['view', 'post', 'upload'], 'releases/123/assets?name=')):
            with self.subTest(point=point):
                result, calls = self.run_release(state=state, replace_draft=point)
                self.assertNotEqual(result, 0)
                self.assertEqual(self.operations(calls), expected)
                self.assertIn(target, calls[-1])
                self.assertFalse(any('456' in call or '654' in call for call in calls))

    def test_stale_draft_asset_blocks_upload_and_publication(self):
        result, calls = self.run_release(state='extra')
        self.assertNotEqual(result, 0)
        self.assertEqual(self.operations(calls), ['view'])

    def test_remote_inventory_must_match_after_upload(self):
        result, calls = self.run_release(state='draft', inventory=['SHA256SUMS'])
        self.assertNotEqual(result, 0)
        self.assertEqual(self.operations(calls), ['view', 'delete'] + ['upload'] * 4)

    def test_same_name_asset_with_wrong_state_size_or_digest_blocks_publication(self):
        for fault in ({'state': 'starter'}, {'size': 0}, {'digest': 'sha256:' + '0' * 64}):
            with self.subTest(fault=fault):
                result, calls = self.run_release(state='draft', asset_fault=fault)
                self.assertNotEqual(result, 0)
                self.assertEqual(self.operations(calls), ['view', 'delete'] + ['upload'] * 4)

    def test_moved_or_deleted_tag_cannot_publish(self):
        for state in ('moved', 'deleted', 'moved-after-upload', 'deleted-after-upload'):
            with self.subTest(state=state):
                result, calls = self.run_release(state='draft', remote_tag=state)
                self.assertNotEqual(result, 0)
                expected = ['view', 'delete'] + ['upload'] * 4 if state.endswith('after-upload') else []
                self.assertEqual(self.operations(calls), expected)

    def test_annotated_tag_resolves_to_the_tested_commit(self):
        result, calls = self.run_release(remote_tag='annotated')
        self.assertEqual(result, 0)
        self.assertIn('api --method PATCH repos/example/test-only/releases/123 ', calls[-1])

    def test_suffix_tag_creates_prerelease(self):
        result, calls = self.run_release(tag='v1.2.3-rc.1')
        self.assertEqual(result, 0)
        self.assertIn('-F prerelease=true', calls[1])
        self.assertIn('-F prerelease=true', calls[-1])


class HelperPublicationTests(ReleasePublicationFixture):
    def test_helper_release_publishes_only_native_helper_archives(self):
        for tag, prerelease in [('helper-v1.2.3', 'false'), ('helper-v1.2.3-rc.1', 'true')]:
            with self.subTest(tag=tag):
                result, calls = self.run_release(tag=tag, profile='helper')
                self.assertEqual(result, 0)
                self.assertEqual(self.operations(calls), ['view', 'post'] + ['upload'] * 3 + ['patch'])
                self.assertIn(f'-f tag_name={tag} ', calls[1])
                self.assertIn(f'-f tag_name={tag} ', calls[-1])
                self.assertIn(f'-F prerelease={prerelease}', calls[1])
                self.assertIn(f'-F prerelease={prerelease}', calls[-1])

    def test_publication_rejects_crossed_tag_namespaces(self):
        for profile, tag in [('standalone', 'helper-v1.2.3'), ('helper', 'v1.2.3')]:
            with self.subTest(profile=profile):
                result, calls = self.run_release(tag=tag, profile=profile)
                self.assertNotEqual(result, 0)
                self.assertEqual(calls, [])


class ReleaseRoutingTests(unittest.TestCase):
    def test_windows_gate_vets_and_tests_only_standalone_packages(self):
        pwsh = shutil.which('pwsh')
        if not pwsh:
            self.skipTest('PowerShell is required to run the Windows workflow step')
        stub = """function go {
          ConvertTo-Json -Compress -InputObject $args
          if ($args[0] -eq 'build') {
            New-Item -ItemType File binary-package/wgslirp.exe | Out-Null
          }
          $global:LASTEXITCODE = 0
        }
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shared = root / 'tools/ci' / GO_SHARED_PACKAGES.name
            shared.parent.mkdir(parents=True)
            shutil.copyfile(GO_SHARED_PACKAGES, shared)
            script = root / 'windows-gate.ps1'
            script.write_text("$ErrorActionPreference = 'Stop'\n" + stub
                              + run_block('Build and test the Windows executable'), encoding='utf-8')
            result = subprocess.run([pwsh, '-NoProfile', '-NonInteractive', '-File', str(script)], cwd=root,
                                    text=True, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            build, vet, unit, integration = map(json.loads, result.stdout.splitlines())
            self.assertEqual(build[-1], './cmd/wgslirp')
            expected = ['./cmd/wgslirp', './cmd/stress_wg_queue', './internal/application',
                        './internal/envconfig', './internal/packetwire', './pkg/...']
            self.assertEqual(vet, ['vet'] + expected)
            self.assertEqual(unit, ['test', '-timeout', '120s', '-count=1'] + expected)
            self.assertEqual(integration[-1], './pkg/wireguard')
            self.assertIn('^(TestReleaseBinary|TestEncryptedWireGuardTCPUDP)$', integration)

    def test_helper_gate_runs_the_shared_runtime_suite_without_the_standalone_binary(self):
        bash = workflow_bash(self)
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / 'env'
            env = os.environ | {'GITHUB_ENV': env_file.as_posix(), 'RELEASE_SCOPE': 'helper'}
            script = ('set -euo pipefail\n' + run_block('Select Go packages', GO_WORKFLOW)
                      + 'export "$(cat "$GITHUB_ENV")"\n'
                      + """go() { printf '%s\\n' "$*"; }\n"""
                      + run_block('Build and vet', GO_WORKFLOW)
                      + run_block('Run tests', GO_WORKFLOW)
                      + run_block('Run integration tests', GO_WORKFLOW))
            result = subprocess.run([bash], input=script, cwd=ROOT, env=env,
                                    text=True, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            packages = './internal/application ./internal/envconfig ./internal/packetwire ./pkg/... ./cmd/wgslirp-helper ./internal/helperwire'
            self.assertEqual(result.stdout.splitlines(), [
                f'build {packages}', f'vet {packages}', f'test -race -timeout 120s -count=1 {packages}',
                f'test -race -tags=integration -timeout 120s -count=1 {packages}',
            ])
        go_workflow = GO_WORKFLOW.read_text(encoding='utf-8')
        self.assertIn("if: env.RELEASE_SCOPE == 'helper'\n"
                      '        run: python3 tools/ci/test_binary_release.py -v HelperPackageTests HelperPublicationTests',
                      go_workflow)

    def test_tag_namespaces_and_job_dependencies_are_disjoint(self):
        standalone = WORKFLOW.read_text(encoding='utf-8')
        helper = HELPER_WORKFLOW.read_text(encoding='utf-8')
        for workflow, pattern in [(standalone, 'v*'), (helper, 'helper-v*')]:
            with self.subTest(pattern=pattern):
                tags = re.findall(r"""^    tags: \[['"]([^'"]+)['"]\]$""", workflow, re.MULTILINE)
                self.assertEqual(tags, [pattern])
        standalone_jobs = standalone.split('\njobs:\n', 1)[1]
        helper_jobs = helper.split('\njobs:\n', 1)[1]
        self.assertNotIn('helper-linux', standalone_jobs)
        self.assertRegex(standalone_jobs, r'(?m)^  release-binaries:\n    needs: \[promote-image, .+, windows-binary\]$')
        self.assertEqual(re.findall(r'^  ([\w-]+):$', helper_jobs, re.MULTILINE),
                         ['test', 'helper-linux', 'helper-windows-tests', 'release-helper'])
        self.assertIn('uses: ./.github/workflows/go.yml\n    with:\n      release-scope: helper\n', helper_jobs)
        windows_tests = helper_jobs.split('  helper-windows-tests:\n', 1)[1].split('  release-helper:', 1)[0]
        self.assertIn("github.ref_type == 'branch'", windows_tests)
        self.assertIn('go test -timeout 120s -count=1 ./cmd/wgslirp-helper ./internal/helperwire', windows_tests)
        self.assertIn('  release-helper:\n    needs: [test, helper-linux]\n', helper_jobs)
        self.assertIn("startsWith(github.ref, 'refs/tags/helper-v')", helper_jobs.split('  release-helper:', 1)[1])


if __name__ == '__main__':
    unittest.main()
