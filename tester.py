import asyncio
import base64
import json
import os
import urllib.parse

from config import XRAY_PATH, stable_config_id
from file_lock_utils import load_json_locked, save_json_locked
from proxy_tester import test_single_config

# ==================== تنظیمات ====================
CUSTOM_INPUT_FILE = "custom_configs.json"
# منابع دیگه‌ی کانفیگ‌های شخصی (همه با is_custom=True ذخیره می‌شن):
#   personal_configs.json → خروجی scraper از کانال شخصی (جایگزین custom_listener)
#   dispatch_configs.json → کانفیگ‌هایی که بات تلگرام لحظه‌ای فرستاده (repository_dispatch)
#   متغیر محیطی CUSTOM_CONFIGS → کانفیگ‌های خصوصی از GitHub Secrets (هر خط یک کانفیگ)
EXTRA_CUSTOM_FILES = ("personal_configs.json", "dispatch_configs.json")
INPUT_FILE = "raw_configs.json"
OUTPUT_FILE = "valid_configs.json"

# روی runner گیت‌هاب ۴ هسته داریم؛ ۵ برای VPS کوچیک بود
CONCURRENCY = int(os.getenv("TEST_CONCURRENCY", "16"))

# پیش‌فیلتر TCP: قبل از بالا آوردن xray فقط چک می‌کنیم پورت سرور باز هست یا نه.
# این تست خیلی ارزونه و معمولاً حدود نصف کانفیگ‌های مرده رو همین‌جا حذف می‌کنه.
TCP_PREFILTER = os.getenv("TCP_PREFILTER", "1") != "0"
TCP_CONCURRENCY = 100
TCP_TIMEOUT_SECONDS = 4
PORT_RANGE_START = 25000
PORT_RANGE_SIZE = 500
SUPPORTED_SCHEMES = ("vless://", "vmess://", "ss://", "trojan://", "hysteria2://", "hy2://")
# =================================================


def get_config_fingerprint(uri: str) -> str | None:
    """
    استخراج مشخصات اتصال (IP, Port, UUID, Transport, Security, SNI)
    برای حذف کانفیگ‌های کاملاً یکسان با نام‌ها (#...) یا پارامترهای ظاهری متفاوت.
    همچنین کانفیگ‌های بدون رمزنگاری یا منسوخ‌شده در ایران را رد می‌کند.
    """
    try:
        uri = uri.strip()
        if not uri.startswith(SUPPORTED_SCHEMES):
            return None

        clean_uri = uri.split("#")[0]

        # ── ۱. پارس VMess ───────────────────────────────────────────
        if uri.startswith("vmess://"):
            b64_part = clean_uri[len("vmess://") :]
            b64_part += "=" * ((4 - len(b64_part) % 4) % 4)
            raw_json = base64.b64decode(b64_part).decode("utf-8", errors="ignore")
            data = json.loads(raw_json)

            add = str(data.get("add", "")).strip().lower()
            port = str(data.get("port", "")).strip()
            uid = str(data.get("id", "")).strip().lower()
            net = str(data.get("net", "tcp")).strip().lower()
            tls = str(data.get("tls", "")).strip().lower()
            path = str(data.get("path", "")).strip()

            # حذف کانفیگ‌های ناامن (VMess TCP بدون TLS در فایروال ایران کار نمی‌کند)
            if net == "tcp" and tls in ("", "none"):
                return None

            return f"vmess:{add}:{port}:{uid}:{net}:{tls}:{path}"

        # ── ۲. پارس VLESS / Trojan / SS / Hysteria ───────────────────
        parsed = urllib.parse.urlparse(clean_uri)
        scheme = parsed.scheme.lower()
        user = parsed.username or ""
        host = (parsed.hostname or "").lower()
        port = parsed.port or ""
        query = urllib.parse.parse_qs(parsed.query)

        net = query.get("type", query.get("net", ["tcp"]))[0].lower()
        security = query.get("security", ["none"])[0].lower()
        path = query.get("path", [""])[0]
        sni = query.get("sni", query.get("host", [""]))[0].lower()
        pbk = query.get("pbk", [""])[0]  # کلید Reality

        # حذف VLESS بدون رمزنگاری (بدون TLS یا Reality)
        if scheme == "vless" and security in ("none", ""):
            return None

        return f"{scheme}:{host}:{port}:{user}:{net}:{security}:{sni}:{pbk}:{path}"

    except Exception:
        return None


def filter_unique_candidates(config_list: list[str], seen_fps: set[str]) -> list[str]:
    """فیلتر کانفیگ‌های سالم با جلوگیری از تست ساختارهای تکراری"""
    unique_list = []
    for cfg in config_list:
        fp = get_config_fingerprint(cfg)
        if fp and fp not in seen_fps:
            seen_fps.add(fp)
            unique_list.append(cfg)
    return unique_list


def get_endpoint(uri: str) -> tuple[str, int, bool] | None:
    """
    (host, port, is_udp) رو از لینک کانفیگ درمیاره.
    اگه پارس نشه None برمی‌گردونه و اون کانفیگ بدون پیش‌فیلتر مستقیم با xray تست می‌شه.
    """
    try:
        uri = uri.strip()
        clean_uri = uri.split("#")[0]
        if uri.startswith("vmess://"):
            b64_part = clean_uri[len("vmess://"):]
            b64_part += "=" * ((4 - len(b64_part) % 4) % 4)
            data = json.loads(base64.b64decode(b64_part).decode("utf-8", errors="ignore"))
            net = str(data.get("net", "tcp")).lower()
            host, port = str(data.get("add", "")).strip(), int(data.get("port", 0))
            is_udp = net in ("kcp", "mkcp", "quic")
        else:
            parsed = urllib.parse.urlparse(clean_uri)
            scheme = parsed.scheme.lower()
            query = urllib.parse.parse_qs(parsed.query)
            net = query.get("type", query.get("net", ["tcp"]))[0].lower()
            host, port = parsed.hostname or "", int(parsed.port or 0)
            is_udp = scheme in ("hysteria2", "hy2", "tuic") or net in ("kcp", "mkcp", "quic")
        if not host or not port:
            return None
        return host, port, is_udp
    except Exception:
        return None


async def _tcp_alive(host: str, port: int, sem: asyncio.Semaphore) -> bool:
    async with sem:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=TCP_TIMEOUT_SECONDS
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            return False


async def tcp_prefilter(uris: list[str]) -> set[str]:
    """
    مجموعه‌ی کانفیگ‌هایی که ارزش تست با xray رو دارن برمی‌گردونه.
    هر endpoint یکتا فقط یک بار connect می‌شه. پروتکل‌های UDP (Hysteria2/TUIC/mKCP/QUIC)
    و کانفیگ‌هایی که endpoint‌شون پارس نمی‌شه، بدون فیلتر رد می‌شن.
    """
    if not TCP_PREFILTER or not uris:
        return set(uris)

    endpoints: dict[tuple[str, int], list[str]] = {}
    passthrough: set[str] = set()
    for uri in uris:
        ep = get_endpoint(uri)
        if ep is None or ep[2]:
            passthrough.add(uri)
        else:
            endpoints.setdefault((ep[0], ep[1]), []).append(uri)

    sem = asyncio.Semaphore(TCP_CONCURRENCY)
    keys = list(endpoints)
    results = await asyncio.gather(*(_tcp_alive(h, p, sem) for h, p in keys))

    alive = set(passthrough)
    for key, ok in zip(keys, results):
        if ok:
            alive.update(endpoints[key])

    print(f"  🔌 پیش‌فیلتر TCP: {len(alive)} از {len(uris)} کانفیگ قبول شدن "
          f"({len(keys)} endpoint یکتا چک شد)")
    return alive


def load_custom_configs() -> list[str]:
    configs: list[str] = list(load_json(CUSTOM_INPUT_FILE, []))
    for path in EXTRA_CUSTOM_FILES:
        configs.extend(load_json(path, []))
    env_configs = os.getenv("CUSTOM_CONFIGS", "")
    configs.extend(line.strip() for line in env_configs.splitlines() if line.strip())
    return [c for c in configs if isinstance(c, str)]


def load_json(path: str, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


async def retest_existing(existing: list[dict], semaphore: asyncio.Semaphore) -> list[dict]:
    tasks = []
    for idx, item in enumerate(existing):
        uri = item.get("config")
        if not uri:
            continue
        port = PORT_RANGE_START + (idx % PORT_RANGE_SIZE)
        tasks.append(_retest_one(item, uri, port, semaphore))

    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]


async def _retest_one(original: dict, uri: str, port: int, semaphore: asyncio.Semaphore) -> dict | None:
    fresh = await test_single_config(uri, port, semaphore, fetch_geo=False)
    if fresh is None:
        return None
    fresh["country"] = original.get("country", fresh.get("country"))
    fresh["country_code"] = original.get("country_code", fresh.get("country_code"))
    fresh["city"] = original.get("city", fresh.get("city"))
    fresh["is_custom"] = original.get("is_custom", False)
    if not fresh.get("ip"):
        fresh["ip"] = original.get("ip", "")
    return fresh


async def main():
    if not os.path.exists(XRAY_PATH):
        print(f"فایل اجرایی Xray در مسیر ({XRAY_PATH}) یافت نشد!")
        return

    semaphore = asyncio.Semaphore(CONCURRENCY)
    merged: dict[str, dict] = {}
    seen_fingerprints: set[str] = set()

    # ── گام ۱: تست کانفیگ‌های دستی (custom_configs.json) ────────────────────
    custom_raw = load_custom_configs()
    unique_custom = filter_unique_candidates(custom_raw, seen_fingerprints)

    if unique_custom:
        print(f"شروع تست {len(unique_custom)} کانفیگ دستی/شخصی یکتا...")
        custom_tasks = []
        for idx, cfg in enumerate(unique_custom):
            port = PORT_RANGE_START + (idx % PORT_RANGE_SIZE)
            custom_tasks.append(test_single_config(cfg, port, semaphore, fetch_geo=True))

        custom_results = await asyncio.gather(*custom_tasks)
        for r in custom_results:
            if r:
                r["is_custom"] = True
                merged[r["id"]] = r
        print(f"  ✅ {len([r for r in custom_results if r])} کانفیگ دستی تایید شد.")

    # ── گام ۲: بازتست کانفیگ‌های موجود در valid_configs.json ───────────────
    existing = load_json_locked(OUTPUT_FILE, [])
    if existing:
        # قبل از retest، خود existing رو هم بر اساس fingerprint یکتا می‌کنیم.
        # این رفع یک باگ قدیمی‌ست: چون فیلتر یکتاسازی قبلاً فقط روی
        # کانفیگ‌های *جدید* (custom/raw) اعمال می‌شد، هر دوتایی که یک‌بار با
        # fingerprint یکسان وارد valid_configs.json شده بودن (مثلاً قبل از
        # اضافه شدن این مکانیزم، یا با تفاوت جزئی در remark/پارامترها)
        # هیچ‌وقت پاک نمی‌شدن؛ هر بار retest می‌شدن و zombie می‌موندن.
        # الان بین دوتای هم‌ارز، اونی که پینگ کمتری داره رو نگه می‌داریم.
        existing_sorted = sorted(existing, key=lambda x: x.get("ping", 99999))
        deduped_existing = []
        for item in existing_sorted:
            fp = get_config_fingerprint(item.get("config", ""))
            if fp is None:
                # کانفیگ ناسازگار با قوانین فعلی (مثلاً پروتکل ناامن) — دورش بنداز
                continue
            if fp in seen_fingerprints:
                continue  # نسخه‌ی بهتر (پینگ کمتر) قبلاً نگه داشته شده
            seen_fingerprints.add(fp)
            deduped_existing.append(item)

        removed_dupes = len(existing) - len(deduped_existing)
        if removed_dupes:
            print(f"  🧹 {removed_dupes} کانفیگ تکراری/نامعتبر از {OUTPUT_FILE} حذف شد.")

        print(f"\nبررسی زنده بودن {len(deduped_existing)} کانفیگ یکتا در {OUTPUT_FILE}...")
        # کانفیگ‌های شخصی همیشه با xray تست می‌شن؛ بقیه اول از پیش‌فیلتر TCP رد می‌شن
        reachable = await tcp_prefilter(
            [i["config"] for i in deduped_existing if not i.get("is_custom") and i.get("config")]
        )
        deduped_existing = [
            i for i in deduped_existing if i.get("is_custom") or i.get("config") in reachable
        ]
        alive_existing = await retest_existing(deduped_existing, semaphore)
        for item in alive_existing:
            merged[item["id"]] = item
        print(f"  ✅ {len(alive_existing)} کانفیگ از قبل زنده نگه‌داشته شدند.")

    # ── گام ۳: فیلتر ساختاری و تست کانفیگ‌های تلگرام (raw_configs.json) ───
    raw_configs = load_json(INPUT_FILE, [])
    # فیلتر تکراری‌ها بر اساس IP/Port/UUID قبل از صرف پردازش و پورت
    unique_new_raw = filter_unique_candidates(raw_configs, seen_fingerprints)
    new_candidates = [c for c in unique_new_raw if stable_config_id(c) not in merged]
    if new_candidates:
        reachable = await tcp_prefilter(new_candidates)
        new_candidates = [c for c in new_candidates if c in reachable]

    if new_candidates:
        print(f"\nشروع تست روی {len(new_candidates)} کانفیگ جدید و غیرتکراری تلگرام...")
        raw_tasks = []
        for idx, cfg in enumerate(new_candidates):
            port = PORT_RANGE_START + (idx % PORT_RANGE_SIZE)
            raw_tasks.append(test_single_config(cfg, port, semaphore, fetch_geo=True))

        raw_results = await asyncio.gather(*raw_tasks)
        for r in raw_results:
            if r:
                r["is_custom"] = False
                merged[r["id"]] = r
        print(f"  ✅ {len([r for r in raw_results if r])} کانفیگ جدید تلگرام تایید شد.")

    # ── گام ۴: مرتب‌سازی بر اساس پینگ و ذخیره نهایی ──────────────────────
    final_list = list(merged.values())
    # چیدمان سریع‌ترین سرورها در بالای لیست برای ارائه به کاربر
    final_list.sort(key=lambda x: x.get("ping", 99999))

    print(f"\nمجموع نهایی: {len(final_list)} کانفیگ سالم و یکتا در {OUTPUT_FILE}.")

    save_json_locked(OUTPUT_FILE, final_list)


if __name__ == "__main__":
    asyncio.run(main())