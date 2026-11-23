"""اختبارات المراقب: موقع محلي، وخادم تيليجرام مزيف، وشهادة SSL تنتهي بعد 5 أيام.
التشغيل: python3 -m unittest -v tests/test_monitor.py
"""
import contextlib
import io
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import monitor  # noqa: E402

FLAKY = {"fail": False}


class Site(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        p = self.path
        if p == "/ok":
            return self.reply(200, "مرحبا بك في الموقع".encode())
        if p == "/fail":
            return self.reply(500, b"error")
        if p == "/slow":
            time.sleep(1.5)
            return self.reply(200, b"slow")
        if p == "/flaky":
            return self.reply(503 if FLAKY["fail"] else 200, b"x")
        self.reply(404, b"nf")

    def reply(self, code, body):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FakeTelegram(BaseHTTPRequestHandler):
    sent, updates, broken = [], [], {"on": False}

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        q = {k: v[0] for k, v in parse_qs(body).items()}
        method = urlparse(self.path).path.rsplit("/", 1)[-1]
        if FakeTelegram.broken["on"]:
            self.send_response(502); self.end_headers(); return
        if method == "sendMessage":
            FakeTelegram.sent.append(q)
            out = {"ok": True, "result": {}}
        else:  # getUpdates
            out = {"ok": True, "result": FakeTelegram.updates[:]}
            FakeTelegram.updates.clear()
        data = json.dumps(out).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)


def serve(handler, tls_ctx=None):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.handle_error = lambda *a: None  # فحص الشهادة يفتح الاتصال ويغلقه بلا طلب
    if tls_ctx:
        srv.socket = tls_ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class MonitorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.site = serve(Site)
        cls.tg = serve(FakeTelegram)
        cls.base = f"http://127.0.0.1:{cls.site.server_port}"
        cls.tls = None
        if shutil.which("openssl"):  # شهادة لـ localhost تنتهي بعد 5 أيام
            crt, key = cls.tmp / "c.pem", cls.tmp / "k.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "5", "-subj", "/CN=localhost",
                            "-addext", "subjectAltName=DNS:localhost", "-keyout", str(key), "-out", str(crt)],
                           check=True, capture_output=True)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(crt, key)
            cls.tls = serve(Site, ctx); cls.crt = crt

    def setUp(self):
        FakeTelegram.sent.clear(); FakeTelegram.updates.clear(); FakeTelegram.broken["on"] = False
        FLAKY["fail"] = False
        self.n = getattr(self, "n", 0) + 1

    def config(self, checks, **mon):
        db = self.tmp / f"{self.id()}.sqlite"
        db.unlink(missing_ok=True)
        m = {"interval": 1, "timeout": 2, "fail_threshold": 2, "retry_delay": 0, "db": str(db), **mon}
        if self.tls and "ca_file" not in mon:
            m["ca_file"] = str(self.crt)
        lines = ['[telegram]', 'token = "123:TEST"', 'chat_id = "42"', f'api = "http://127.0.0.1:{self.tg.server_port}"', '[monitor]']
        lines += [f"{k} = {json.dumps(v)}" for k, v in m.items()]
        for c in checks:
            lines.append("[[check]]")
            lines += [f"{k} = {json.dumps(v, ensure_ascii=False)}" for k, v in c.items()]
        p = self.tmp / f"{self.id()}.toml"
        p.write_text("\n".join(lines), encoding="utf-8")
        return p

    def rounds(self, cfg, n):
        for _ in range(n):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                monitor.main(["once", "-c", str(cfg)])

    def texts(self):
        return [m["text"] for m in FakeTelegram.sent]

    def test_healthy_site_sends_nothing(self):
        cfg = self.config([{"name": "الموقع", "url": self.base + "/ok", "keyword": "مرحبا"}])
        self.rounds(cfg, 3)
        self.assertEqual(self.texts(), [])

    def test_down_only_after_threshold_then_recovery(self):
        cfg = self.config([{"name": "متجر", "url": self.base + "/flaky"}])
        FLAKY["fail"] = True
        self.rounds(cfg, 1)
        self.assertEqual(self.texts(), [], "فشل واحد لا يكفي للتنبيه")
        self.rounds(cfg, 1)
        self.assertEqual(len(self.texts()), 1)
        self.assertIn("🔴", self.texts()[0]); self.assertIn("HTTP 503", self.texts()[0])
        self.rounds(cfg, 2)
        self.assertEqual(len(self.texts()), 1, "لا نكرر التنبيه ما دام متوقفاً")
        FLAKY["fail"] = False
        time.sleep(1.1)
        self.rounds(cfg, 1)
        self.assertEqual(len(self.texts()), 2)
        self.assertIn("✅", self.texts()[1]); self.assertIn("مدة التوقف", self.texts()[1])

    def test_keyword_missing(self):
        cfg = self.config([{"name": "k", "url": self.base + "/ok", "keyword": "غير موجودة"}], fail_threshold=1)
        self.rounds(cfg, 1)
        self.assertIn("غير موجودة في الصفحة", self.texts()[0])

    def test_status_code_mismatch_and_404(self):
        cfg = self.config([{"name": "x", "url": self.base + "/missing"}], fail_threshold=1)
        self.rounds(cfg, 1)
        self.assertIn("HTTP 404 (المتوقع 200)", self.texts()[0])

    def test_timeout(self):
        cfg = self.config([{"name": "بطيء", "url": self.base + "/slow"}], fail_threshold=1, timeout=1)
        self.rounds(cfg, 1)
        self.assertTrue(any(s in self.texts()[0] for s in ("لم يرد خلال", "انتهت المهلة")), self.texts())

    def test_dns_failure(self):
        cfg = self.config([{"name": "dns", "url": "http://no-such-host.invalid/"}], fail_threshold=1)
        self.rounds(cfg, 1)
        self.assertIn("DNS", self.texts()[0])

    def test_tcp_port_closed(self):
        cfg = self.config([{"name": "قاعدة", "tcp": f"127.0.0.1:{free_port()}"}], fail_threshold=1)
        self.rounds(cfg, 1)
        self.assertIn("مرفوض", self.texts()[0])

    def test_tcp_port_open(self):
        cfg = self.config([{"name": "web", "tcp": f"127.0.0.1:{self.site.server_port}"}], fail_threshold=1)
        self.rounds(cfg, 2)
        self.assertEqual(self.texts(), [])

    @unittest.skipUnless(shutil.which("openssl"), "openssl غير موجود")
    def test_ssl_expiry_warning_once_a_day(self):
        cfg = self.config([{"name": "آمن", "url": f"https://localhost:{self.tls.server_port}/ok"}], ssl_warn_days=14)
        self.rounds(cfg, 3)
        warn = [t for t in self.texts() if "شهادة" in t]
        self.assertEqual(len(warn), 1, self.texts())
        self.assertRegex(warn[0], "تنتهي بعد (4 أيام|5 أيام)")

    @unittest.skipUnless(shutil.which("openssl"), "openssl غير موجود")
    def test_untrusted_certificate_is_down(self):
        cfg = self.config([{"name": "شهادة", "url": f"https://localhost:{self.tls.server_port}/ok"}], fail_threshold=1, ca_file="")
        self.rounds(cfg, 1)
        self.assertIn("شهادة SSL غير صالحة", self.texts()[0])

    def test_outbox_keeps_messages_when_telegram_is_down(self):
        cfg = self.config([{"name": "m", "url": self.base + "/fail"}], fail_threshold=1)
        FakeTelegram.broken["on"] = True
        self.rounds(cfg, 1)
        self.assertEqual(self.texts(), [])
        FakeTelegram.broken["on"] = False
        self.rounds(cfg, 1)
        self.assertEqual(len(self.texts()), 1, "الرسالة المؤجلة وصلت، ولم يتكرر التنبيه")
        self.assertIn("🔴", self.texts()[0])

    def test_status_command_only_for_owner(self):
        cfg = self.config([{"name": "الموقع", "url": self.base + "/ok"}])
        FakeTelegram.updates.extend([
            {"update_id": 1, "message": {"chat": {"id": 999}, "text": "/status"}},
            {"update_id": 2, "message": {"chat": {"id": 42}, "text": "/status"}},
        ])
        with contextlib.redirect_stdout(io.StringIO()):
            monitor.main(["serve", "-c", str(cfg), "--rounds", "1"])
        tg, mon, checks = monitor.load_config(cfg)
        db = monitor.open_db(mon["db"])
        monitor.poll_commands(db, tg, checks, mon, 1)
        monitor.flush_outbox(db, tg)
        self.assertEqual(len(self.texts()), 1, "رد واحد فقط: للمالك")
        self.assertIn("🟢 الموقع", self.texts()[0])
        self.assertEqual(FakeTelegram.sent[0]["chat_id"], "42")

    def test_html_in_name_is_escaped(self):
        cfg = self.config([{"name": "<b>x</b>", "url": self.base + "/fail"}], fail_threshold=1)
        self.rounds(cfg, 1)
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", self.texts()[0])

    def test_duration_and_days_wording(self):
        self.assertEqual(monitor.duration(200), "3 دقائق و20 ثانية")
        self.assertEqual(monitor.duration(125), "دقيقتان و5 ثوانٍ")
        self.assertEqual(monitor.duration(3601), "ساعة وثانية")
        self.assertEqual(monitor.days_ar(2), "يومين")
        self.assertEqual(monitor.days_ar(5), "5 أيام")


if __name__ == "__main__":
    unittest.main()
