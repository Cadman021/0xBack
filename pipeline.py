"""
pipeline.py — جایگزین runner.py
================================
runner.py یک حلقه‌ی بی‌نهایت بود که سرور رو همیشه روشن نگه می‌داشت.
این فایل فقط *یک* چرخه اجرا می‌کنه و تموم می‌شه؛ زمان‌بندی رو cron در
GitHub Actions انجام می‌ده (.github/workflows/update.yml).

اجرای لوکال:  python pipeline.py
"""
import asyncio
import os
import sys

from config import XRAY_PATH
from publish import main as run_publish
from scraper import main as run_scraper
from tester import main as run_tester


async def run_once() -> int:
    if not os.path.exists(XRAY_PATH):
        print(f"❌ فایل اجرایی Xray در مسیر ({XRAY_PATH}) یافت نشد!")
        return 1

    print("========== ۱. جمع‌آوری از تلگرام ==========")
    try:
        await run_scraper()
    except Exception as e:
        # اگه تلگرام در دسترس نبود، باز هم کانفیگ‌های قبلی رو بازتست و منتشر می‌کنیم
        print(f"⚠️ خطا در scraper (ادامه با کانفیگ‌های قبلی): {e}")

    print("\n========== ۲. تست با Xray ==========")
    await run_tester()

    print("\n========== ۳. ساخت خروجی استاتیک ==========")
    run_publish()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(run_once()))
