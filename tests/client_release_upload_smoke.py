"""Exercise client EXE publishing through PHP's real multipart upload path."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
CLIENT_VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
_version_parts = CLIENT_VERSION.split(".")
PREVIOUS_VERSION = "{0}.{1}.{2}".format(_version_parts[0], _version_parts[1], max(0, int(_version_parts[2]) - 1))
DEFAULT_INSTALLER = ROOT / "artifacts/client-installer/{0}/NovaProtect-Setup-{0}.exe".format(CLIENT_VERSION)


def installer_release_notes() -> str:
    """The installer description is the release-notes source of truth."""
    version_iss = (ROOT / "installer/version.iss").read_text(encoding="utf-8")
    match = re.search(r'^#define MyAppVersionComments "([^"]*)"', version_iss, re.MULTILINE)
    if not match:
        raise SystemExit("installer/version.iss is missing MyAppVersionComments")
    return match.group(1)


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def check(value: bool, message: str) -> None:
    if not value:
        raise AssertionError(message)
    print("[ OK ] " + message)


def upload(connection: http.client.HTTPConnection, installer: Path, boundary: str) -> http.client.HTTPResponse:
    fields = {
        "minimum_version": PREVIOUS_VERSION,
        "force_update": "0",
        "release_notes": "",
    }
    pieces: list[bytes] = []
    for name, value in fields.items():
        pieces.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n".encode()
        )
    pieces.append(
        (f"--{boundary}\r\nContent-Disposition: form-data; name=\"client_installer\"; "
         f"filename=\"NovaProtect-Setup-{CLIENT_VERSION}-rebuild.EXE\"\r\n"
         "Content-Type: application/vnd.microsoft.portable-executable\r\n\r\n").encode()
    )
    prefix = b"".join(pieces)
    suffix = f"\r\n--{boundary}--\r\n".encode()
    length = len(prefix) + installer.stat().st_size + len(suffix)
    connection.putrequest("POST", "/")
    connection.putheader("Content-Type", f"multipart/form-data; boundary={boundary}")
    connection.putheader("Content-Length", str(length))
    connection.endheaders()
    connection.send(prefix)
    with installer.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            connection.send(chunk)
    connection.send(suffix)
    return connection.getresponse()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--php", default=shutil.which("php"), help="PHP CLI executable")
    parser.add_argument("--installer", type=Path, default=DEFAULT_INSTALLER)
    args = parser.parse_args()
    if not args.php:
        raise SystemExit("PHP CLI is required")
    installer = args.installer.resolve()
    if not installer.is_file():
        raise SystemExit(f"Missing client installer: {installer}")

    probe = r'''require "website/app/bootstrap.php";
$_SERVER["CONTENT_TYPE"] = "multipart/form-data; boundary=smoke";
$_SERVER["CONTENT_LENGTH"] = "9000000";
exit(np_request_exceeds_post_max_size() ? 0 : 1);'''
    oversized = subprocess.run([args.php, "-d", "post_max_size=8M", "-r", probe], cwd=ROOT, capture_output=True, text=True)
    check(oversized.returncode == 0, "PHP post_max_size overflow is detected after the body is discarded")

    with tempfile.TemporaryDirectory(prefix="np-client-upload-") as work:
        base = Path(work)
        data = base / "data"
        releases = base / "releases"
        upload_tmp = base / "upload-tmp"
        document_root = base / "public"
        for folder in (data, releases, upload_tmp, document_root):
            folder.mkdir()
        (data / "client_release.json").write_text(json.dumps({
            "clientVersion": PREVIOUS_VERSION,
            "fileName": f"NovaProtect-Setup-{PREVIOUS_VERSION}.exe",
            "sha256": "0" * 64,
        }), encoding="utf-8")
        (document_root / "index.php").write_text("""<?php
require getenv('NP_TEST_BOOTSTRAP');
header('Content-Type: application/json; charset=utf-8');
try {
    $record = np_upload_client_release($_FILES['client_installer'] ?? [], $_POST['minimum_version'] ?? '', ($_POST['force_update'] ?? '') === '1', $_POST['release_notes'] ?? '', 'upload-smoke');
    http_response_code(201);
    echo json_encode($record, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
} catch (InvalidArgumentException $exception) {
    http_response_code(422);
    echo json_encode(['error' => $exception->getMessage()], JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
}
""", encoding="utf-8")

        environment = os.environ.copy()
        environment.update({
            "NOVAPROTECT_DATA_DIR": str(data).replace("\\", "/"),
            "NOVAPROTECT_RELEASE_DIR": str(releases).replace("\\", "/"),
            "NP_TEST_BOOTSTRAP": str(ROOT / "website/app/bootstrap.php").replace("\\", "/"),
        })
        log_path = base / "php-server.log"
        with log_path.open("wb") as log:
            port = free_port()
            process = subprocess.Popen([
                args.php,
                "-d", "upload_max_filesize=1024M",
                "-d", "post_max_size=260M",
                "-d", "max_execution_time=900",
                "-d", "max_input_time=900",
                "-d", "upload_tmp_dir=" + str(upload_tmp).replace("\\", "/"),
                "-S", f"127.0.0.1:{port}", "-t", str(document_root),
            ], cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT)
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError(log_path.read_text(encoding="utf-8", errors="replace"))
                    try:
                        probe = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                        probe.request("GET", "/")
                        probe.getresponse().read()
                        probe.close()
                        break
                    except OSError:
                        time.sleep(0.1)
                else:
                    raise TimeoutError("PHP built-in server did not start")

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=900)
                response = upload(connection, installer, "----NovaProtectUploadSmokeBoundary")
                payload = json.loads(response.read())
                connection.close()
                check(response.status == 201, f"multipart installer upload accepted (HTTP {response.status}: {payload})")
                check(payload["clientVersion"] == CLIENT_VERSION, "client version is read from PE metadata")
                check(payload["fileName"] == f"NovaProtect-Setup-{CLIENT_VERSION}.exe", "uploaded EXE gets a canonical versioned name")
                expected_notes = installer_release_notes()
                check(expected_notes in payload["releaseNotes"], "release notes come from the installer description")
                saved = releases / payload["fileName"]
                check(saved.is_file() and saved.stat().st_size == installer.stat().st_size, "validated installer is saved in release storage")
                def digest(path: Path) -> str:
                    value = hashlib.sha256()
                    with path.open("rb") as stream:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                            value.update(chunk)
                    return value.hexdigest()
                check(digest(saved) == digest(installer) == payload["sha256"], "stored installer SHA-256 matches the upload")
                invalid_installer = base / "not-an-exe.EXE"
                invalid_installer.write_bytes(b"not a Windows PE executable")
                invalid_connection = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
                invalid_response = upload(invalid_connection, invalid_installer, "----NovaProtectInvalidUploadBoundary")
                invalid_payload = json.loads(invalid_response.read())
                invalid_connection.close()
                check(invalid_response.status == 422 and "Windows PE EXE" in invalid_payload.get("error", ""), "non-PE upload is rejected with a specific format error")
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)


if __name__ == "__main__":
    main()
