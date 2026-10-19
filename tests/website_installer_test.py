"""Run the shipped Bash entry points without changing any server state."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
OPTIONS = argparse.Namespace(package=None, bash=None, kind="full")


def shell_path(path: Path) -> str:
    return str(path.resolve()).replace("\\", "/")


def find_bash() -> Path:
    candidates = [OPTIONS.bash, os.environ.get("NOVAPROTECT_TEST_BASH"), shutil.which("bash"), shutil.which("sh")]
    git = shutil.which("git")
    if git:
        candidates.append(str(Path(git).resolve().parents[1] / "usr/bin/sh.exe"))
    for candidate in candidates:
        if not candidate or not Path(candidate).is_file():
            continue
        result = subprocess.run([candidate, "--version"], capture_output=True, timeout=10)
        if result.returncode == 0 and b"GNU bash" in result.stdout:
            return Path(candidate).resolve()
    raise RuntimeError("Bash is required; pass --bash /path/to/bash or set NOVAPROTECT_TEST_BASH")


class WebsiteInstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kind = OPTIONS.kind
        cls.bash = find_bash()
        cls.temporary = tempfile.TemporaryDirectory(prefix="novaprotect-installer-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.base = Path(cls.temporary.name)
        cls.bundle = cls.base / "NovaProtect 上传包 with spaces"
        cls.bundle.mkdir()
        cls.outside = cls.base / "unrelated working directory"
        cls.outside.mkdir()
        if OPTIONS.package:
            with zipfile.ZipFile(OPTIONS.package) as archive:
                archive.extractall(cls.bundle)
        else:
            # Source-only tests use the same file layout as the release archive.
            for name in ("app", "public"):
                shutil.copytree(ROOT / "website" / name, cls.bundle / name,
                                ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copytree(ROOT / "website" / "deploy", cls.bundle / "deploy",
                            ignore=shutil.ignore_patterns("install.sh", "entry-install.sh")
                            if cls.kind == "upgrade" else None)
            for name in ("VERSION", "release.json"):
                shutil.copyfile(ROOT / "website" / name, cls.bundle / name)
            shutil.copyfile(ROOT / "website/upgrade.sh", cls.bundle / "upgrade.sh")
            if cls.kind == "full":
                shutil.copyfile(ROOT / "website/deploy/entry-install.sh", cls.bundle / "install.sh")
            (cls.bundle / "downloads").mkdir()
            (cls.bundle / "downloads/fixture.exe").write_bytes(b"local package checksum fixture\n")
            rows = []
            for path in sorted(cls.bundle.rglob("*")):
                if path.is_file():
                    rows.append(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.relative_to(cls.bundle).as_posix())
            # Explicit LF: Windows text mode would otherwise rewrite every
            # newline to CRLF and sha256sum --check would look for files whose
            # names end with a carriage return.
            (cls.bundle / "SHA256SUMS").write_text("\n".join(rows) + "\n", encoding="utf-8", newline="\n")

        cls.environment = os.environ.copy()
        cls.environment["PATH"] = str(cls.bash.parent) + os.pathsep + cls.environment.get("PATH", "")
        cls.environment["LC_ALL"] = "C.UTF-8"
        probe = subprocess.run([str(cls.bash), "-c", "command -v sha256sum"],
                               capture_output=True, env=cls.environment, timeout=10)
        if probe.returncode:
            if os.name != "nt":
                raise RuntimeError("sha256sum is required for the installer tests")
            # The bundled Windows Git omits sha256sum. This adapter computes
            # real SHA-256 hashes; it does not bypass the manifest check.
            helper = cls.base / "sha256sum.py"
            helper.write_text('''import hashlib
from pathlib import Path
import re
import sys
if sys.argv[1:] != ["--check", "SHA256SUMS", "--quiet"]:
    raise SystemExit("Unexpected sha256sum adapter arguments")
failed = False
for line in Path("SHA256SUMS").read_text(encoding="utf-8").splitlines():
    match = re.fullmatch(r"([a-f0-9]{64})  (.+)", line)
    if not match:
        raise SystemExit("Invalid checksum manifest")
    file = Path(match[2])
    try:
        with file.open("rb") as stream:
            digest = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1048576), b""):
                digest.update(chunk)
            actual = digest.hexdigest()
    except OSError:
        actual = None
    if actual != match[1]:
        print(f"{file}: FAILED", file=sys.stderr)
        failed = True
raise SystemExit(1 if failed else 0)
''', encoding="utf-8")
            adapter_dir = cls.base / "test-tools"
            adapter_dir.mkdir()
            adapter = adapter_dir / "sha256sum"
            adapter.write_bytes(("#!/usr/bin/sh\nexec " + shlex.quote(shell_path(Path(sys.executable))) +
                                 " -B " + shlex.quote(shell_path(helper)) + ' "$@"\n').encode("utf-8"))
            adapter.chmod(0o755)
            cls.environment["PATH"] = str(adapter_dir) + os.pathsep + cls.environment["PATH"]
            print("SHA-256 adapter: Python hashlib (Windows Bash lacks sha256sum)", file=sys.stderr)

    def run_installer(self, script: str, cwd: Path | None = None, arguments=None):
        return subprocess.run([str(self.bash), shell_path(self.bundle / script),
                               *(arguments if arguments is not None else ["--check-package"])],
                              cwd=cwd or self.bundle, env=self.environment,
                              capture_output=True, encoding="utf-8", errors="replace", timeout=60)

    def assert_package_ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PACKAGE-CHECK-OK", result.stdout)
        self.assertIn((self.bundle / "VERSION").read_text().strip(), result.stdout)
        self.assertNotIn("/deploy/VERSION", result.stdout + result.stderr)
        self.assertFalse((self.bundle / "releases").exists())
        self.assertFalse((self.bundle / "data").exists())

    def test_root_entry_from_package_root(self):
        if self.kind != "full":
            self.skipTest("full-install entry points are not in an upgrade package")
        self.assert_package_ok(self.run_installer("install.sh"))

    def test_root_entry_from_other_working_directory(self):
        if self.kind != "full":
            self.skipTest("full-install entry points are not in an upgrade package")
        self.assert_package_ok(self.run_installer("install.sh", self.outside))

    def test_deploy_entry_from_deploy_directory(self):
        if self.kind != "full":
            self.skipTest("full-install entry points are not in an upgrade package")
        self.assert_package_ok(self.run_installer("deploy/install.sh", self.bundle / "deploy"))

    def test_deploy_entry_from_other_working_directory(self):
        if self.kind != "full":
            self.skipTest("full-install entry points are not in an upgrade package")
        self.assert_package_ok(self.run_installer("deploy/install.sh", self.outside))

    def test_upgrade_entry_from_package_root(self):
        result = self.run_installer("upgrade.sh", arguments=["--check-package"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("UPGRADE-PACKAGE-CHECK-OK", result.stdout)
        self.assertNotIn("/deploy/VERSION", result.stdout + result.stderr)

    def test_deploy_upgrade_entry_from_other_working_directory(self):
        result = self.run_installer("deploy/upgrade.sh", self.outside, ["--check-package"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("UPGRADE-PACKAGE-CHECK-OK", result.stdout)

    def test_upgrade_package_has_no_full_install_entry(self):
        if self.kind != "upgrade":
            self.skipTest("only upgrade packages omit full-install entry points")
        for name in ("install.sh", "deploy/install.sh", "deploy/entry-install.sh"):
            self.assertFalse((self.bundle / name).exists(), name)

    def test_missing_version_is_reported_before_server_checks(self):
        path = self.bundle / "VERSION"
        original = path.read_bytes()
        try:
            path.unlink()
            entry = "install.sh" if self.kind == "full" else "upgrade.sh"
            result = self.run_installer(entry)
        finally:
            path.write_bytes(original)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("包不完整", result.stderr)
        self.assertNotIn("No such file or directory", result.stderr)

    def test_corrupt_payload_is_rejected(self):
        path = self.bundle / "app/bootstrap.php"
        original = path.read_bytes()
        try:
            path.write_bytes(original + b"\n// checksum regression fixture\n")
            entry = "install.sh" if self.kind == "full" else "upgrade.sh"
            result = self.run_installer(entry)
        finally:
            path.write_bytes(original)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAILED", result.stderr + result.stdout)
        self.assertNotIn("PACKAGE-CHECK-OK", result.stdout)

    def test_unknown_argument_is_rejected(self):
        entry = "install.sh" if self.kind == "full" else "upgrade.sh"
        result = self.run_installer(entry, arguments=["--unknown"])
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("用法", result.stderr)

    def php_binary(self):
        if not hasattr(self, "_php_cache"):
            candidate = os.environ.get("NOVAPROTECT_TEST_PHP") or shutil.which("php")
            self._php_cache = None
            if candidate:
                probe = subprocess.run([candidate, "-v"], capture_output=True, timeout=30)
                if probe.returncode == 0:
                    self._php_cache = candidate
        return self._php_cache

    def require_php(self):
        php = self.php_binary()
        if not php:
            self.skipTest("PHP CLI is required for the admin password reset tests")
        return php

    def make_data_dir(self, name, installed=True):
        data = self.base / name
        (data / "sessions").mkdir(parents=True)
        if installed:
            (data / "installation.json").write_text('{"installed":true,"websiteVersion":"test"}', encoding="utf-8")
        return data

    def write_verify_helper(self):
        helper = self.base / "verify_password.php"
        helper.write_text(
            "<?php\n"
            "require $argv[1];\n"
            "$hash = np_admin_password_hash();\n"
            "exit(is_string($hash) && np_verify_password($argv[2], $hash) ? 0 : 1);\n",
            encoding="utf-8")
        return helper

    def password_verifies(self, php, helper, data_dir, password):
        environment = os.environ.copy()
        environment["NOVAPROTECT_DATA_DIR"] = str(data_dir)
        result = subprocess.run([php, shell_path(helper), shell_path(self.bundle / "app" / "bootstrap.php"), password],
                                env=environment, capture_output=True, timeout=120)
        return result.returncode == 0

    def run_reset(self, *arguments, stdin=None, data_dir=None):
        command = [self.require_php(), shell_path(self.bundle / "deploy" / "reset-admin-password.php"), *arguments]
        if data_dir is not None:
            command += ["--data-dir", shell_path(data_dir)]
        environment = os.environ.copy()
        if data_dir is not None:
            environment["NOVAPROTECT_DATA_DIR"] = str(data_dir)
        return subprocess.run(command, cwd=self.bundle, env=environment, input=stdin,
                              capture_output=True, encoding="utf-8", errors="replace", timeout=180)

    def link_current(self, release: Path, slot: Path):
        """Point <slot> at <release> like install.sh does; fall back to a copy
        when symlinks are unavailable (or silently skipped by a sandbox)."""
        try:
            os.symlink(release, slot, target_is_directory=True)
        except (OSError, NotImplementedError, AttributeError):
            pass
        if not os.path.lexists(slot):
            shutil.copytree(release / "app", slot / "app")

    def make_installed_layout(self, name, with_site_root=True):
        """Reproduce the on-server layout: <state>/bin plus <site-root>/current -> releases/<version>."""
        root = self.base / name
        state = root / "state"
        site = root / "site"
        (state / "bin").mkdir(parents=True)
        release = site / "releases" / "2.2.14"
        shutil.copytree(self.bundle / "app", release / "app")
        self.link_current(release, site / "current")
        shutil.copyfile(self.bundle / "deploy" / "reset-admin-password.php",
                        state / "bin" / "reset-admin-password.php")
        if with_site_root:
            (state / "site-root").write_text(str(site) + "\n", encoding="utf-8")
        return state, site

    def run_installed_reset(self, state, *arguments, stdin=None, data_dir=None):
        command = [self.require_php(), shell_path(state / "bin" / "reset-admin-password.php"), *arguments]
        if data_dir is not None:
            command += ["--data-dir", shell_path(data_dir)]
        environment = os.environ.copy()
        environment.pop("NOVAPROTECT_APP_DIR", None)
        if data_dir is not None:
            environment["NOVAPROTECT_DATA_DIR"] = str(data_dir)
        return subprocess.run(command, cwd=shell_path(state), env=environment, input=stdin,
                              capture_output=True, encoding="utf-8", errors="replace", timeout=180)

    def test_reset_admin_password_tool_is_cli_only(self):
        script = (self.bundle / "deploy" / "reset-admin-password.php").read_text(encoding="utf-8")
        self.assertIn("PHP_SAPI !== 'cli'", script)
        self.assertIn("np_set_admin_password", script)
        self.assertIn("NOVAPROTECT_DATA_DIR", script)

    def test_reset_admin_password_usage_lists_ssh_command(self):
        result = self.run_reset("--help")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("/www/server/novaprotect/bin/reset-admin-password.php", result.stdout)
        self.assertIn("--data-dir", result.stdout)

    def test_reset_admin_password_rejects_unknown_argument(self):
        data = self.make_data_dir("reset-unknown-data")
        result = self.run_reset("--bogus", data_dir=data)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("未知参数", result.stderr)
        self.assertFalse((data / "admin.json").exists())

    def test_reset_admin_password_end_to_end(self):
        php = self.require_php()
        data = self.make_data_dir("reset-e2e-data")
        for name in ("sess_alpha", "sess_beta"):
            (data / "sessions" / name).write_text("stale", encoding="utf-8")
        (data / "sessions" / "notes.txt").write_text("keep", encoding="utf-8")
        helper = self.write_verify_helper()

        seeded = self.run_reset("--force", "--password", "Seed-Password-123", data_dir=data)
        self.assertEqual(seeded.returncode, 0, seeded.stdout + seeded.stderr)
        self.assertIn("RESET-OK", seeded.stdout)
        seeded_sessions = re.search(r"已失效后台会话：(\d+)", seeded.stdout)
        self.assertIsNotNone(seeded_sessions, seeded.stdout)
        self.assertEqual(seeded_sessions.group(1), "2")
        self.assertTrue(self.password_verifies(php, helper, data, "Seed-Password-123"))

        result = self.run_reset("--password", "Rotated-Password-456", data_dir=data)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("RESET-OK", result.stdout)
        self.assertFalse(self.password_verifies(php, helper, data, "Seed-Password-123"))
        self.assertTrue(self.password_verifies(php, helper, data, "Rotated-Password-456"))
        self.assertFalse((data / "sessions" / "sess_alpha").exists())
        self.assertFalse((data / "sessions" / "sess_beta").exists())
        self.assertTrue((data / "sessions" / "notes.txt").exists())

        (data / "sessions" / "sess_gamma").write_text("stale", encoding="utf-8")
        kept = self.run_reset("--keep-sessions", "--password", "Third-Password-789", data_dir=data)
        self.assertEqual(kept.returncode, 0, kept.stdout + kept.stderr)
        self.assertTrue(self.password_verifies(php, helper, data, "Third-Password-789"))
        self.assertTrue((data / "sessions" / "sess_gamma").exists())

    def test_reset_admin_password_rejects_short_password(self):
        data = self.make_data_dir("reset-short-data")
        result = self.run_reset("--force", "--password", "short", data_dir=data)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("10 到 128", result.stderr)
        self.assertFalse((data / "admin.json").exists())

    def test_reset_admin_password_requires_matching_confirmation(self):
        data = self.make_data_dir("reset-mismatch-data")
        result = self.run_reset(data_dir=data, stdin="Password-One-1\nPassword-Two-2\n")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("两次输入不一致", result.stderr)
        self.assertFalse((data / "admin.json").exists())

    def test_reset_admin_password_generates_usable_password(self):
        php = self.require_php()
        data = self.make_data_dir("reset-generate-data")
        result = self.run_reset("--generate=24", data_dir=data)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        match = re.search(r"生成的新口令：(\S+)", result.stdout)
        self.assertIsNotNone(match, result.stdout)
        generated = match.group(1)
        self.assertGreaterEqual(len(generated), 16)
        self.assertTrue(self.password_verifies(php, self.write_verify_helper(), data, generated))

    def test_reset_admin_password_requires_installed_state(self):
        data = self.make_data_dir("reset-uninstalled-data", installed=False)
        result = self.run_reset("--password", "Refused-Password-1", data_dir=data)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("安装向导", result.stderr)
        self.assertFalse((data / "admin.json").exists())

    def test_install_scripts_record_site_root(self):
        for name in ("deploy/install.sh", "deploy/upgrade.sh"):
            path = self.bundle / name
            if not path.exists():
                continue
            self.assertIn('"$state/site-root"', path.read_text(encoding="utf-8"), name)

    def test_reset_admin_password_locates_app_via_site_root(self):
        state, site = self.make_installed_layout("installed-locate")
        result = self.run_installed_reset(state, "--locate")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        expected = Path(os.path.realpath(site / "current")) / "app"
        self.assertIn("APP-DIR " + shell_path(expected), result.stdout)

    def test_reset_admin_password_installed_layout_end_to_end(self):
        php = self.require_php()
        state, site = self.make_installed_layout("installed-e2e")
        data = self.make_data_dir("installed-e2e-data")
        helper = self.write_verify_helper()

        seeded = self.run_installed_reset(state, "--force", "--password", "Installed-Password-1", data_dir=data)
        self.assertEqual(seeded.returncode, 0, seeded.stdout + seeded.stderr)
        self.assertIn("RESET-OK", seeded.stdout)
        self.assertTrue(self.password_verifies(php, helper, data, "Installed-Password-1"))

        rotated = self.run_installed_reset(state, "--password", "Installed-Password-2", data_dir=data)
        self.assertEqual(rotated.returncode, 0, rotated.stdout + rotated.stderr)
        self.assertFalse(self.password_verifies(php, helper, data, "Installed-Password-1"))
        self.assertTrue(self.password_verifies(php, helper, data, "Installed-Password-2"))

    def test_reset_admin_password_locates_state_current_without_site_root(self):
        root = self.base / "state-current"
        state = root / "state"
        release = root / "release"
        (state / "bin").mkdir(parents=True)
        shutil.copytree(self.bundle / "app", release / "app")
        shutil.copyfile(self.bundle / "deploy" / "reset-admin-password.php",
                        state / "bin" / "reset-admin-password.php")
        self.link_current(release, state / "current")
        result = self.run_installed_reset(state, "--locate")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        expected = Path(os.path.realpath(state / "current")) / "app"
        self.assertIn("APP-DIR " + shell_path(expected), result.stdout)

    def test_reset_admin_password_reports_missing_app_dir_with_hints(self):
        if Path("/www/wwwroot").exists() or Path("/www/server/novaprotect").exists():
            self.skipTest("real deployment directories exist on this host")
        state = self.base / "missing-app" / "state"
        (state / "bin").mkdir(parents=True)
        shutil.copyfile(self.bundle / "deploy" / "reset-admin-password.php",
                        state / "bin" / "reset-admin-password.php")
        result = self.run_installed_reset(state, "--locate")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("找不到网站 app 目录", result.stderr)
        self.assertIn("/www/wwwroot/<域名>/current/app", result.stderr)
        self.assertIn("--app=", result.stderr)

    def test_shipped_shell_scripts_parse(self):
        for script in sorted(self.bundle.rglob("*.sh")):
            with self.subTest(script=script.relative_to(self.bundle)):
                self.assertNotIn(b"\r", script.read_bytes())
                result = subprocess.run([str(self.bash), "-n", shell_path(script)],
                                        capture_output=True, timeout=10, env=self.environment)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, help="test an actual release ZIP instead of the source layout")
    parser.add_argument("--bash", help="Bash executable (bundled Git sh.exe is also supported)")
    parser.add_argument("--kind", choices=("full", "upgrade"), default="full",
                        help="package shape to test")
    OPTIONS, remaining = parser.parse_known_args()
    unittest.main(argv=[sys.argv[0], *remaining], verbosity=2)
