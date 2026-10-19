"""Offline BaoTa/Nginx configuration regression tests."""

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("nginx_cfg", root / "website/deploy/configure_nginx.py")
cfg = importlib.util.module_from_spec(spec)
assert spec.loader is not None
# Register before exec so dataclasses (and similar introspection) can resolve
# the module through sys.modules on Python 3.12+.
sys.modules[spec.name] = cfg
spec.loader.exec_module(cfg)
template = (root / "website/deploy/nginx-location.conf").read_text(encoding="utf-8")


class BaoTaConfigTests(unittest.TestCase):
    def render(self, original: str) -> str:
        return cfg.configure(
            original,
            template,
            "unix:/tmp/php-cgi-84.sock",
            "/www/wwwroot/nova.fbi.plus/current/public",
        )

    def test_fresh(self):
        result = self.render("")
        self.assertIn("server_name nova.fbi.plus;", result)
        self.assertIn("fastcgi_pass unix:/tmp/php-cgi-84.sock;", result)
        self.assertIn("include enable-php-84.conf;", result)
        self.assertIn("root /www/wwwroot/nova.fbi.plus/current/public;", result)
        self.assertIn("location = /admin", result)
        self.assertIn("client_max_body_size 260m;", result)
        self.assertIn("client_body_timeout 300s;", result)
        self.assertNotIn("proxy_pass", result)

    def test_existing_baota_tls(self):
        original = '''# BaoTa normal PHP/static site
server {
  listen 80;
  listen 443 ssl;
  server_name nova.fbi.plus www.nova.fbi.plus;
  root /www/wwwroot/nova.fbi.plus;
  ssl_certificate /www/server/panel/vhost/cert/nova.fbi.plus/fullchain.pem;
  ssl_certificate_key /www/server/panel/vhost/cert/nova.fbi.plus/privkey.pem;
  ssl_protocols TLSv1.2 TLSv1.3;
  include enable-php-82.conf;
  include /www/server/panel/vhost/rewrite/nova.fbi.plus.conf;
  if ($scheme = http) { return 301 https://$host$request_uri; }
  location ~ \\.(css|js|png)$ { expires 30d; }
  location ~ \\.php$ { return 404; }
}
'''
        result = self.render(original)
        self.assertIn("listen 443 ssl;", result)
        self.assertIn("ssl_certificate_key", result)
        self.assertIn("include enable-php-84.conf;", result)
        self.assertNotIn("enable-php-82.conf", result)
        self.assertNotIn("expires 30d", result)
        self.assertNotIn("return 301", result)
        self.assertIn("fastcgi_param HTTP_X_FORWARDED_PROTO https;", result)
        self.assertIn("location ^~ /.well-known/acme-challenge/", result)

    def test_unrelated_server_unchanged(self):
        other = 'server { listen 81; server_name other.example; root "/tmp/{x}"; }'
        original = other + '\nserver { listen 80; server_name nova.fbi.plus; }\n'
        result = self.render(original)
        self.assertTrue(result.startswith(other))
        self.assertIn("fastcgi_pass unix:/tmp/php-cgi-84.sock;", result)

    def test_dedicated_http_https_blocks(self):
        original = 'server { listen 80; server_name nova.fbi.plus; }\nserver { listen 443 ssl; server_name nova.fbi.plus; ssl_certificate "a#b.pem"; ssl_certificate_key "key.pem"; }'
        result = self.render(original)
        self.assertEqual(result.count("fastcgi_pass unix:/tmp/php-cgi-84.sock;"), 2)
        self.assertEqual(result.count("listen 80;"), 1)
        self.assertIn('"a#b.pem"', result)

    def test_other_domain_rejected(self):
        with self.assertRaises(ValueError):
            self.render('server { listen 80; server_name nova.fbi.plus.attacker; }')

    def test_indirect_tls_rejected_safely(self):
        with self.assertRaises(ValueError):
            self.render('server { listen 443 ssl; server_name nova.fbi.plus; include ssl.conf; }')

    def test_malformed_rejected(self):
        for original in ['server {', 'server { listen 80; } }', 'server { listen "80; }']:
            with self.assertRaises(ValueError):
                self.render(original)

    def test_idempotent(self):
        result = self.render("")
        rebuilt = self.render(result)
        self.assertEqual(rebuilt.count("fastcgi_pass unix:/tmp/php-cgi-84.sock;"), 1)
        self.assertIn("include enable-php-84.conf;", rebuilt)
        self.assertIn("root /www/wwwroot/nova.fbi.plus/current/public;", rebuilt)
        self.assertNotIn("@@PHP_SOCKET@@", rebuilt)

    def test_configurator_command_writes_candidate(self):
        with tempfile.TemporaryDirectory(prefix="novaprotect-nginx-") as directory:
            output = Path(directory) / "new-vhost.conf"
            result = subprocess.run([
                sys.executable, "-B", str(root / "website/deploy/configure_nginx.py"),
                "--input", str(Path(directory) / "not-installed.conf"),
                "--output", str(output),
                "--php-socket", "unix:/tmp/php-cgi-84.sock",
                "--document-root", "/www/wwwroot/nova.fbi.plus/current/public",
            ], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("NGINX-CONFIG-READY", result.stdout)
            self.assertIn("fastcgi_pass unix:/tmp/php-cgi-84.sock;", output.read_text(encoding="utf-8"))
            self.assertIn("include enable-php-84.conf;", output.read_text(encoding="utf-8"))
            self.assertNotIn(b"\r", output.read_bytes())


if __name__ == "__main__":
    unittest.main(verbosity=2)
