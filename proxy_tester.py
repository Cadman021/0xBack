"""
ماژول مشترک بین main.py و tester.py
منطق مشترک تست زنده‌بودن یک کانفیگ (پینگ + موقعیت جغرافیایی).
استفاده‌شده در:
- tester.py برای تست دسته‌جمعی کانفیگ‌های خام
- main.py برای رفرش لحظه‌ای پینگ (وقتی کاربر دکمه‌ی "Test Ping" رو در افزونه میزنه)
- tester.py برای re-test کردن کانفیگ‌های موجود در valid_configs.json (بررسی زنده بودن)
"""
import asyncio
import json
import os
import subprocess
import time

from aiohttp import ClientSession, ClientTimeout
from aiohttp_socks import ProxyConnector

from config import XRAY_PATH, create_xray_config, parse_uri, stable_config_id

TEST_URL         = "https://www.gstatic.com/generate_204"
GEO_URL          = "http://ip-api.com/json"
TIMEOUT_SECONDS  = 9
# قبلاً 1.2 ثانیه بود؛ برای پروتکل‌های سنگین (VLESS-Reality/XTLS) که uTLS
# handshake سنگینی دارن این کافی نبود، مخصوصاً وقتی چند پردازه‌ی xray
# هم‌زمان بالا میان و برای CPU رقابت می‌کنن.
XRAY_STARTUP_WAIT_SECONDS = 2.0
MAX_ATTEMPTS = 2  # یک بار retry قبل از اینکه کانفیگ رو "مرده" اعلام کنیم


async def _probe_once(uri: str, port: int, xray_config: dict, fetch_geo: bool) -> dict | None:
  """یک تلاش برای بالا آوردن xray و زدن تست generate_204 (+ اختیاری GeoIP)."""
  temp_path = f"temp_cfg_{port}.json"
  with open(temp_path, "w", encoding="utf-8") as f:
    json.dump(xray_config, f)

  proc = subprocess.Popen(
      [XRAY_PATH, "-config", temp_path],
      stdout=subprocess.DEVNULL,
      stderr=subprocess.DEVNULL,
  )

  await asyncio.sleep(XRAY_STARTUP_WAIT_SECONDS)

  result = None
  try:
    connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{port}")
    timeout   = ClientTimeout(total=TIMEOUT_SECONDS)
    async with ClientSession(connector=connector, timeout=timeout) as session:
      t0 = time.time()
      async with session.get(TEST_URL) as resp:
        if resp.status in (200, 204):
          ping_ms = int((time.time() - t0) * 1000)
          _, network = parse_uri(uri)

          # ── GeoIP کاملاً مستقل از سلامت اتصاله ──────────────────────────
          # اگه GeoIP fail بشه (rate-limit روی ip-api.com یا timeout)، این
          # نباید باعث حذف یا نامعتبر شدن کانفیگ بشه؛ فقط کشور رو "Unknown"
          # می‌ذاریم و کانفیگ همچنان معتبر و سالم باقی می‌مونه.
          geo = {}
          if fetch_geo:
            try:
              async with session.get(GEO_URL) as geo_resp:
                if geo_resp.status == 200:
                  geo = await geo_resp.json()
            except Exception:
              geo = {}

          result = {
              "id":              stable_config_id(uri),
              "config":          uri,
              "ping":            ping_ms,
              "country":         geo.get("country") or "Unknown",
              "country_code":    geo.get("countryCode", "").lower() or None,
              "city":            geo.get("city"),
              "ip":              geo.get("query", ""),
              "transport":       network,
              "is_wasm_compatible": network == "ws",
              "last_tested":     int(time.time()),
          }
  except Exception:
    pass
  finally:
    proc.kill()
    proc.wait()
    if os.path.exists(temp_path):
      os.remove(temp_path)

  return result


async def test_single_config(
    uri: str, port: int, semaphore: asyncio.Semaphore, fetch_geo: bool = True
) -> dict | None:
  """
  یک کانفیگ رو با اجرای یک پردازه‌ی موقت xray تست می‌کنه.
  fetch_geo=False برای re-test سریع (فقط می‌خوایم بدونیم زنده‌ست یا نه و پینگ چقدره،
  کشور/شهر از قبل معلومه و نیازی به کوئری دوباره‌ی geo API نیست).

  چون تست‌ها همزمان (concurrent) اجرا میشن و رقابت روی CPU می‌تونه باعث
  false-negative بشه (کانفیگ سالمی که فقط تصادفاً توی اون لحظه‌ی شلوغ
  جواب نداده)، قبل از اعلام "مرده"، یک بار دیگه هم امتحان می‌کنیم.
  """
  async with semaphore:
    xray_config = create_xray_config(uri, port)
    if not xray_config:
      return None

    for attempt in range(MAX_ATTEMPTS):
      result = await _probe_once(uri, port, xray_config, fetch_geo)
      if result is not None:
        return result
      if attempt < MAX_ATTEMPTS - 1:
        await asyncio.sleep(0.5)  # یه نفس کوچیک قبل از تلاش دوم

    return None
