"""
publish.py — جایگزین public_api.py
====================================
به جای یک سرور FastAPI که همیشه روشنه، همون خروجی‌ها رو یک بار بعد از هر تست
به‌صورت فایل استاتیک می‌سازه و GitHub Pages / Cloudflare Pages سرو می‌کنن.

نگاشت endpointهای قدیمی به فایل‌های جدید:
  GET /api/v1/candidates                         →  /api/v1/candidates.json
  GET /api/v1/health                             →  /api/v1/health.json
  GET /api/v1/xray-config?config_id=X            →  /api/v1/xray/X.json
  GET /api/v1/xray-config?config_id=X&adblock=1  →  /api/v1/xray/X.adblock.json

فایل‌های اضافه:
  /sub/configs.txt , /sub/configs_base64.txt     لینک subscription برای v2rayNG/Hiddify
  /state/valid_configs.json                      وضعیت کامل؛ اجرای بعدی از همین ادامه می‌ده
"""
import base64
import json
import os
import shutil
import time
from collections import Counter

from config import DATA_FILE, create_xray_config

OUT_DIR = os.getenv("PUBLISH_DIR", "public")
MOBILE_LOCAL_SOCKS_PORT = 10808  # پورت قراردادی SOCKS محلی روی خود گوشی


def load_valid_configs() -> list[dict]:
    if not os.path.exists(DATA_FILE):
        return []
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def build_candidates(configs: list[dict]) -> dict:
    """دقیقاً همون منطق /api/v1/candidates در public_api.py قدیمی"""
    valid_items = [item for item in configs if item.get("id") and item.get("config")]

    city_counter = Counter(
        (
            (item.get("country_code") or "xx").lower(),
            (item.get("city") or "Unknown City").strip(),
        )
        for item in valid_items
    )
    city_tracker: dict[tuple[str, str], int] = {}

    data = []
    for item in valid_items:
        code = (item.get("country_code") or "xx").lower()
        city = (item.get("city") or "Unknown City").strip()
        key = (code, city)

        if city_counter[key] > 1:
            idx = city_tracker.get(key, 0) + 1
            city_tracker[key] = idx
            display_city = f"{city} #{idx}"
        else:
            display_city = city

        data.append(
            {
                "id": item.get("id"),
                "config": item.get("config"),
                "country": item.get("country") or "Unknown",
                "country_code": item.get("country_code"),
                "city": display_city,
                "is_custom": item.get("is_custom", False),
                "transport": item.get("transport"),
            }
        )

    return {"status": "success", "count": len(data), "data": data}


def _write_json(path: str, obj) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))


def main():
    configs = load_valid_configs()

    # هر بار از صفر می‌سازیم تا فایل xray کانفیگ‌های مرده باقی نمونه
    if os.path.exists(OUT_DIR):
        shutil.rmtree(OUT_DIR)
    os.makedirs(OUT_DIR)

    candidates = build_candidates(configs)
    _write_json(f"{OUT_DIR}/api/v1/candidates.json", candidates)
    _write_json(
        f"{OUT_DIR}/api/v1/health.json",
        {"status": "ok", "updated_at": int(time.time()), "count": candidates["count"]},
    )

    built = 0
    for item in candidates["data"]:
        for adblock, suffix in ((False, ""), (True, ".adblock")):
            xray_json = create_xray_config(
                item["config"], MOBILE_LOCAL_SOCKS_PORT, enable_adblock=adblock
            )
            if not xray_json:
                continue
            _write_json(
                f"{OUT_DIR}/api/v1/xray/{item['id']}{suffix}.json",
                {
                    "status": "success",
                    "xray_config": xray_json,
                    "local_socks_port": MOBILE_LOCAL_SOCKS_PORT,
                },
            )
            built += 1

    plain = "\n".join(i["config"] for i in candidates["data"])
    os.makedirs(f"{OUT_DIR}/sub", exist_ok=True)
    with open(f"{OUT_DIR}/sub/configs.txt", "w", encoding="utf-8") as f:
        f.write(plain)
    with open(f"{OUT_DIR}/sub/configs_base64.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode(plain.encode("utf-8")).decode("ascii"))

    _write_json(f"{OUT_DIR}/state/valid_configs.json", configs)

    # جلوگیری از پردازش Jekyll روی GitHub Pages
    open(f"{OUT_DIR}/.nojekyll", "w").close()
    with open(f"{OUT_DIR}/index.html", "w", encoding="utf-8") as f:
        f.write(
            "<!doctype html><meta charset=utf-8><title>Veloce</title>"
            f"<p>Veloce API — {candidates['count']} configs — "
            f"updated {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}</p>"
        )

    print(f"📦 انتشار: {candidates['count']} کانفیگ، {built} فایل xray در '{OUT_DIR}/'")


if __name__ == "__main__":
    main()
