"""
ماژول مشترک برای خواندن/نوشتن امن فایل valid_configs.json
هم tester.py (چرخه‌ی ۳۰ دقیقه‌ای) و هم custom_listener.py (لحظه‌ای)
هم‌زمان به این فایل دسترسی دارن، پس بدون قفل ممکنه:
- یکی وسط نوشتن دیگری، فایل رو بخونه و JSON ناقص/خراب بگیره
- هر دو هم‌زمان بنویسن و کار یکی از بین بره (لغو شدن نوشته‌ی دیگری)

اینجا از پکیج filelock استفاده می‌کنیم (قفل مبتنی بر فایل .lock کنار خود
فایل اصلی) که بین پردازه‌های مختلف پایتون هم کار می‌کنه، نه فقط thread ها.
"""
import json
import os

from filelock import FileLock

LOCK_TIMEOUT_SECONDS = 30


def _lock_path(path: str) -> str:
    return f"{path}.lock"


def load_json_locked(path: str, default):
    """خواندن امن یک فایل JSON، با قفل، تا وسط نوشتن یه پردازه‌ی دیگه گرفتار نشیم."""
    if not os.path.exists(path):
        return default

    lock = FileLock(_lock_path(path), timeout=LOCK_TIMEOUT_SECONDS)
    with lock:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return default


def save_json_locked(path: str, data) -> None:
    """نوشتن امن یک فایل JSON با قفل. نوشتن atomic (فایل موقت + rename)
    تا اگه وسط نوشتن قطع بشه، فایل اصلی خراب نشه."""
    lock = FileLock(_lock_path(path), timeout=LOCK_TIMEOUT_SECONDS)
    with lock:
        tmp_path = f"{path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, path)


def merge_config_locked(path: str, new_item: dict, dedup_key_fn) -> None:
    """
    یک کانفیگ تکی رو با قفل، به فایل valid_configs.json اضافه/به‌روزرسانی می‌کنه.
    برای استفاده‌ی custom_listener.py که کانفیگ‌ها رو یکی‌یکی و لحظه‌ای اضافه می‌کنه
    (برخلاف tester.py که کل فایل رو یکجا rewrite می‌کنه).

    dedup_key_fn: تابعی که روی یک آیتم صدا زده میشه و fingerprint اون رو برمی‌گردونه؛
    اگه کانفیگ جدید fingerprint یکسانی با یکی از موجودها داشته باشه، جایگزینش می‌کنیم
    (نه اینکه هر دو رو نگه داریم).
    """
    lock = FileLock(_lock_path(path), timeout=LOCK_TIMEOUT_SECONDS)
    with lock:
        try:
            with open(path, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            existing = []

        new_fp = dedup_key_fn(new_item.get("config", ""))

        filtered = []
        for item in existing:
            if item.get("id") == new_item.get("id"):
                continue  # همون کانفیگ (URI یکسان) — حذفش می‌کنیم تا نسخه‌ی تازه جاش بیاد
            if new_fp and dedup_key_fn(item.get("config", "")) == new_fp:
                continue  # هم‌ارز ساختاری (fingerprint یکسان) — قدیمی رو حذف کن
            filtered.append(item)

        filtered.append(new_item)
        filtered.sort(key=lambda x: x.get("ping", 99999))

        tmp_path = f"{path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(filtered, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, path)
