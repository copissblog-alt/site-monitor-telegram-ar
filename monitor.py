#!/usr/bin/env python3
"""مراقب مواقع ينبّهك على تيليجرام — ملف واحد، بلا مكتبات خارجية (Python 3.11+).

الأوامر:
  python3 monitor.py serve            يعمل باستمرار: يفحص كل interval ثانية ويرد على /status في تيليجرام
  python3 monitor.py once             جولة فحص واحدة ثم يخرج (للتشغيل من cron)
  python3 monitor.py status           حالة كل الفحوص في الطرفية
  python3 monitor.py test-telegram    يرسل رسالة تجربة ليتأكد من التوكن ورقم المحادثة
  أضف -c مسار/config.toml لملف إعداد في مكان آخر
"""
from __future__ import annotations

import argparse
import html
import json
import socket
import sqlite3
import ssl
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.0"
UA = f"site-monitor-ar/{VERSION} (+https://github.com/copissblog-alt/site-monitor-telegram-ar)"
DEFAULTS = {"interval": 60, "timeout": 10, "fail_threshold": 2, "retry_delay": 2, "slow_ms": 3000,
            "ssl_warn_days": 14, "summary_hour": None, "db": "monitor.sqlite", "ca_file": None, "keep_days": 30}


# ---------------------------------------------------------------- الإعداد
@dataclass
class Check:
    name: str
    url: str | None = None
    tcp: str | None = None
    expect_status: int = 200
    keyword: str | None = None

    @property
    def target(self) -> str:
        return self.url or f"tcp://{self.tcp}"


def load_config(path: Path) -> tuple[dict, dict, list[Check]]:
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    tg = raw.get("telegram", {})
    mon = {**DEFAULTS, **raw.get("monitor", {})}
    checks = []
    for c in raw.get("check", []):
        if not c.get("name") or not (c.get("url") or c.get("tcp")):
            sys.exit(f"كل [[check]] يحتاج name و url أو tcp: {c}")
        checks.append(Check(name=c["name"], url=c.get("url"), tcp=c.get("tcp"),
                            expect_status=int(c.get("expect_status", 200)), keyword=c.get("keyword")))
    if len({c.name for c in checks}) != len(checks):
        sys.exit("أسماء الفحوص يجب أن تكون مختلفة")
    db = Path(mon["db"])
    mon["db"] = str(db if db.is_absolute() else path.parent / db)
    return tg, mon, checks


# ---------------------------------------------------------------- قاعدة البيانات
SCHEMA = """
CREATE TABLE IF NOT EXISTS results (name TEXT, ts INTEGER, ok INTEGER, ms INTEGER, detail TEXT);
CREATE INDEX IF NOT EXISTS results_name_ts ON results(name, ts);
CREATE TABLE IF NOT EXISTS state (name TEXT PRIMARY KEY, status TEXT, since INTEGER, fails INTEGER, detail TEXT, ssl_day TEXT);
CREATE TABLE IF NOT EXISTS outbox (id INTEGER PRIMARY KEY, ts INTEGER, text TEXT);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);
"""


def open_db(path: str) -> sqlite3.Connection:
    db = sqlite3.connect(path, timeout=10)
    db.row_factory = sqlite3.Row
    db.executescript("PRAGMA journal_mode=WAL;" + SCHEMA)
    return db


def kv_get(db, k, default=None):
    r = db.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
    return r["v"] if r else default


def kv_set(db, k, v):
    db.execute("INSERT INTO kv(k, v) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))


# ---------------------------------------------------------------- الفحوص
def ssl_context(mon: dict) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=mon["ca_file"]) if mon["ca_file"] else ssl.create_default_context()


def check_http(c: Check, mon: dict) -> tuple[bool, int, str]:
    req = urllib.request.Request(c.url, headers={"User-Agent": UA})
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=mon["timeout"], context=ssl_context(mon)) as r:
            body = r.read(1_000_000)
            code = r.status
    except urllib.error.HTTPError as e:
        code, body = e.code, b""
    except urllib.error.URLError as e:
        return False, int((time.monotonic() - t0) * 1000), explain(e.reason)
    except (TimeoutError, socket.timeout):
        return False, int((time.monotonic() - t0) * 1000), f"لم يرد خلال {mon['timeout']} ثانية"
    except Exception as e:  # noqa: BLE001
        return False, int((time.monotonic() - t0) * 1000), explain(e)
    ms = int((time.monotonic() - t0) * 1000)
    if code != c.expect_status:
        return False, ms, f"HTTP {code} (المتوقع {c.expect_status})"
    if c.keyword and c.keyword.encode() not in body:
        return False, ms, f"الكلمة «{c.keyword}» غير موجودة في الصفحة"
    return True, ms, f"HTTP {code}"


def check_tcp(c: Check, mon: dict) -> tuple[bool, int, str]:
    host, _, port = c.tcp.rpartition(":")
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, int(port)), timeout=mon["timeout"]):
            pass
    except Exception as e:  # noqa: BLE001
        return False, int((time.monotonic() - t0) * 1000), explain(e)
    return True, int((time.monotonic() - t0) * 1000), "المنفذ مفتوح"


def explain(e) -> str:
    s = str(e)
    if isinstance(e, socket.gaierror) or "Name or service not known" in s or "getaddrinfo" in s:
        return "الدومين لا يُحل في DNS"
    if "CERTIFICATE_VERIFY_FAILED" in s:
        why = s.split("certificate verify failed:")[-1].split("(_ssl")[0].strip(" )>")
        return "شهادة SSL غير صالحة: " + why
    if "Connection refused" in s:
        return "الاتصال مرفوض: لا شيء يستمع على المنفذ"
    if "timed out" in s:
        return "انتهت المهلة"
    return s[:200]


def ssl_days_left(c: Check, mon: dict) -> int | None:
    if not c.url or not c.url.startswith("https://"):
        return None
    u = urllib.parse.urlsplit(c.url)
    try:
        with socket.create_connection((u.hostname, u.port or 443), timeout=mon["timeout"]) as s:
            with ssl_context(mon).wrap_socket(s, server_hostname=u.hostname) as t:
                not_after = t.getpeercert()["notAfter"]
    except Exception:  # noqa: BLE001  (الفحص الأساسي سيبلغ عن المشكلة)
        return None
    return int((ssl.cert_time_to_seconds(not_after) - time.time()) // 86400)


def run_check(c: Check, mon: dict) -> tuple[bool, int, str]:
    fn = check_http if c.url else check_tcp
    ok, ms, detail = fn(c, mon)
    if not ok and mon["retry_delay"] >= 0:
        time.sleep(mon["retry_delay"])  # محاولة ثانية قبل أن نحسبه فشلاً: تمنع تنبيهات الانقطاع اللحظي
        ok, ms, detail = fn(c, mon)
    return ok, ms, detail


# ---------------------------------------------------------------- الرسائل
def esc(s) -> str:
    return html.escape(str(s), quote=False)


def ar_count(n: int, one: str, two: str, few: str, many: str) -> str:
    """العدد مع المعدود بالعربية: ثانية، ثانيتان، 3 ثوانٍ، 11 ثانية"""
    if n == 1:
        return one
    if n == 2:
        return two
    return f"{n} {few if 3 <= n % 100 <= 10 else many}"


def duration(sec: int) -> str:
    sec = max(0, int(sec))
    d, r = divmod(sec, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    out = []
    if d:
        out.append(ar_count(d, "يوم", "يومان", "أيام", "يوماً"))
    if h:
        out.append(ar_count(h, "ساعة", "ساعتان", "ساعات", "ساعة"))
    if m:
        out.append(ar_count(m, "دقيقة", "دقيقتان", "دقائق", "دقيقة"))
    if s:
        out.append(ar_count(s, "ثانية", "ثانيتان", "ثوانٍ", "ثانية"))
    return " و".join(out[:2]) if out else "أقل من ثانية"


def clock(ts: int) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def msg_down(c, detail, since):
    return f"🔴 <b>{esc(c.name)}</b> متوقف\n{esc(c.target)}\nالسبب: {esc(detail)}\nمنذ: {clock(since)}"


def msg_up(c, down_for, ms):
    return f"✅ <b>{esc(c.name)}</b> عاد للعمل\nمدة التوقف: {duration(down_for)}\nزمن الرد الآن: {ms} ms"


def days_ar(n: int) -> str:
    return {1: "يوم واحد", 2: "يومين"}.get(n) or ar_count(n, "", "", "أيام", "يوماً")


def msg_ssl(c, days):
    when = "انتهت صلاحيتها" if days < 0 else ("تنتهي اليوم" if days == 0 else f"تنتهي بعد {days_ar(days)}")
    return f"⚠️ شهادة SSL لـ <b>{esc(c.name)}</b> {when}\n{esc(c.target)}"


def stats_24h(db, name) -> tuple[float | None, int | None, int]:
    r = db.execute("SELECT COUNT(*) n, SUM(ok) up, AVG(CASE WHEN ok THEN ms END) avg FROM results WHERE name=? AND ts>?",
                   (name, int(time.time()) - 86400)).fetchone()
    if not r["n"]:
        return None, None, 0
    return 100.0 * r["up"] / r["n"], int(r["avg"]) if r["avg"] is not None else None, r["n"]


def status_text(db, checks, mon, title="📋 الحالة الآن") -> str:
    lines = [f"<b>{title}</b>"]
    for c in checks:
        st = db.execute("SELECT * FROM state WHERE name=?", (c.name,)).fetchone()
        up, avg, n = stats_24h(db, c.name)
        last = db.execute("SELECT ms FROM results WHERE name=? ORDER BY ts DESC LIMIT 1", (c.name,)).fetchone()
        icon = "⚪" if not st else ("🔴" if st["status"] == "down" else ("🟡" if last and last["ms"] > mon["slow_ms"] else "🟢"))
        extra = f" · {up:.2f}% خلال 24 ساعة · متوسط {avg} ms" if up is not None and avg is not None else ""
        if st and st["status"] == "down":
            extra = f" · متوقف منذ {duration(int(time.time()) - st['since'])}: {esc(st['detail'])}"
        lines.append(f"{icon} {esc(c.name)}{extra}")
    return "\n".join(lines)


# ---------------------------------------------------------------- تيليجرام
def tg_call(tg: dict, method: str, params: dict, timeout: int = 15) -> dict:
    url = f"{tg.get('api', 'https://api.telegram.org').rstrip('/')}/bot{tg['token']}/{method}"
    data = urllib.parse.urlencode(params).encode()
    with urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=timeout) as r:
        return json.loads(r.read())


def queue(db, text: str):
    db.execute("INSERT INTO outbox(ts, text) VALUES(?, ?)", (int(time.time()), text))


def flush_outbox(db, tg) -> int:
    """يرسل الرسائل المنتظرة. إن فشل تيليجرام تبقى في الصندوق وتُرسل في الجولة التالية."""
    sent = 0
    for r in db.execute("SELECT id, text FROM outbox ORDER BY id").fetchall():
        try:
            tg_call(tg, "sendMessage", {"chat_id": tg["chat_id"], "text": r["text"], "parse_mode": "HTML",
                                        "disable_web_page_preview": "true"})
        except Exception as e:  # noqa: BLE001
            print(f"telegram: لم تُرسل الرسالة {r['id']}، ستُعاد لاحقاً: {e}", file=sys.stderr)
            break
        db.execute("DELETE FROM outbox WHERE id=?", (r["id"],))
        db.commit()
        sent += 1
    return sent


def poll_commands(db, tg, checks, mon, wait: int):
    """ينتظر أوامر /status و /help حتى wait ثانية (long polling)، ولا يرد إلا على المحادثة المسموحة."""
    offset = int(kv_get(db, "tg_offset", 0))
    t0 = time.monotonic()
    try:
        res = tg_call(tg, "getUpdates", {"offset": offset, "timeout": max(1, wait), "allowed_updates": '["message"]'},
                      timeout=wait + 10)
    except Exception as e:  # noqa: BLE001
        print(f"telegram getUpdates: {e}", file=sys.stderr)
        time.sleep(min(wait, 10))
        return
    if not res.get("result") and time.monotonic() - t0 < 1:
        time.sleep(min(wait, 2))  # رد فوري بلا رسائل: لا ندور في حلقة سريعة
    for u in res.get("result", []):
        kv_set(db, "tg_offset", u["update_id"] + 1)
        m = u.get("message") or {}
        if str(m.get("chat", {}).get("id")) != str(tg["chat_id"]):
            continue  # غرباء يكتبون للبوت: نتجاهلهم
        cmd = (m.get("text") or "").split("@")[0].strip()
        if cmd == "/status":
            queue(db, status_text(db, checks, mon))
        elif cmd in ("/help", "/start"):
            queue(db, "الأوامر:\n/status حالة كل المواقع الآن")
    db.commit()


# ---------------------------------------------------------------- الجولة
def run_round(db, checks, mon) -> list[str]:
    now = int(time.time())
    with ThreadPoolExecutor(max_workers=min(16, len(checks) or 1)) as pool:
        results = list(pool.map(lambda c: (c, *run_check(c, mon)), checks))
    log = []
    today = datetime.now().strftime("%Y-%m-%d")
    for c, ok, ms, detail in results:
        db.execute("INSERT INTO results VALUES(?, ?, ?, ?, ?)", (c.name, now, int(ok), ms, detail))
        st = db.execute("SELECT * FROM state WHERE name=?", (c.name,)).fetchone()
        status, since, fails = (st["status"], st["since"], st["fails"]) if st else ("up", now, 0)
        if ok:
            if status == "down":
                queue(db, msg_up(c, now - since, ms))
                status, since = "up", now
            fails = 0
        else:
            fails += 1
            if status == "up" and fails == 1:
                since = now  # أول فشل: منه تُحسب مدة التوقف
            if status == "up" and fails >= mon["fail_threshold"]:
                status = "down"
                queue(db, msg_down(c, detail, since))
        db.execute("INSERT INTO state(name, status, since, fails, detail, ssl_day) VALUES(?, ?, ?, ?, ?, ?) "
                   "ON CONFLICT(name) DO UPDATE SET status=excluded.status, since=excluded.since, fails=excluded.fails, detail=excluded.detail",
                   (c.name, status, since, fails, detail, None))
        # الشهادة: مرة واحدة في اليوم على الأكثر
        if ok and c.url and c.url.startswith("https://") and (not st or st["ssl_day"] != today):
            days = ssl_days_left(c, mon)
            if days is not None and days <= mon["ssl_warn_days"]:
                queue(db, msg_ssl(c, days))
            db.execute("UPDATE state SET ssl_day=? WHERE name=?", (today, c.name))
        log.append(f"{'OK  ' if ok else 'FAIL'} {c.name:<20} {ms:>6} ms  {detail}  [{status}, fails={fails}]")
    db.execute("DELETE FROM results WHERE ts < ?", (now - mon["keep_days"] * 86400,))
    db.commit()
    return log


def maybe_summary(db, checks, mon):
    h = mon["summary_hour"]
    if h is None:
        return
    now = datetime.now()
    key = now.strftime("%Y-%m-%d")
    if now.hour >= int(h) and kv_get(db, "summary_day") != key:
        queue(db, status_text(db, checks, mon, title=f"📊 ملخص {key}"))
        kv_set(db, "summary_day", key)
        db.commit()


# ---------------------------------------------------------------- الواجهة
def main(argv=None):
    ap = argparse.ArgumentParser(description="مراقب مواقع ينبّهك على تيليجرام")
    ap.add_argument("command", choices=["serve", "once", "status", "test-telegram"])
    ap.add_argument("-c", "--config", default=str(Path(__file__).with_name("config.toml")))
    ap.add_argument("--rounds", type=int, default=0, help=argparse.SUPPRESS)  # للاختبارات: عدد جولات serve
    a = ap.parse_args(argv)
    tg, mon, checks = load_config(Path(a.config))
    db = open_db(mon["db"])
    try:
        return run(a, db, tg, mon, checks)
    finally:
        db.close()


def run(a, db, tg, mon, checks):
    if a.command == "status":
        print(html.unescape(status_text(db, checks, mon)).replace("<b>", "").replace("</b>", ""))
        return 0
    if a.command == "test-telegram":
        queue(db, f"👋 مراقب المواقع يعمل. سأراقب {len(checks)} فحصاً كل {mon['interval']} ثانية.")
        db.commit()
        return 0 if flush_outbox(db, tg) else 1
    if a.command == "once":
        print("\n".join(run_round(db, checks, mon)))
        maybe_summary(db, checks, mon)
        flush_outbox(db, tg)
        return 0

    rounds = 0
    while True:
        t0 = time.monotonic()
        print(time.strftime("%H:%M:%S"), "\n".join(run_round(db, checks, mon)), flush=True)
        maybe_summary(db, checks, mon)
        flush_outbox(db, tg)
        rounds += 1
        if a.rounds and rounds >= a.rounds:
            return 0
        left = mon["interval"] - (time.monotonic() - t0)
        while left > 0:
            poll_commands(db, tg, checks, mon, int(min(left, 50)))
            flush_outbox(db, tg)
            left = mon["interval"] - (time.monotonic() - t0)


if __name__ == "__main__":
    sys.exit(main())
