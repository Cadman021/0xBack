"""
scraper.py — نسخه‌ی بدون لاگین (بدون Telethon / API_ID / session)
=================================================================
به جای وصل شدن به اکانت تلگرام، نسخه‌ی وب عمومی کانال‌ها رو می‌خونه:
    https://t.me/s/<channel>
این صفحه برای هر کانال عمومی بدون لاگین در دسترسه و با پارامتر ?before=<id>
می‌شه به پیام‌های قدیمی‌تر رفت. پس:
  - هیچ فایل .session یا API_HASH لازم نیست (امن برای repo عمومی)
  - ریسک بن شدن اکانت به‌خاطر لاگین از IP دیتاسنتر GitHub وجود نداره

خروجی‌ها:
  raw_configs.json       کانفیگ‌های کانال‌های عمومی (TELEGRAM_CHANNELS)
  personal_configs.json  کانفیگ‌های کانال شخصی (TELEGRAM_PERSONAL_CHANNEL) — با is_custom=True تست می‌شن
"""
import asyncio
import json
import os
import re

from aiohttp import ClientSession, ClientTimeout
from bs4 import BeautifulSoup

try:  # برای اجرای لوکال؛ روی GitHub Actions لازم نیست
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ==================== تنظیمات ====================
# چند کانال رو با کاما جدا کن: "ConfigsHUB,AnotherChannel"
CHANNELS = [
    c.strip().lstrip("@")
    for c in os.getenv("TELEGRAM_CHANNELS", os.getenv("TELEGRAM_CHANNEL", "ConfigsHUB")).split(",")
    if c.strip()
]
PERSONAL_CHANNEL = os.getenv("TELEGRAM_PERSONAL_CHANNEL", "").strip().lstrip("@")
LIMIT_MESSAGES = int(os.getenv("LIMIT_MESSAGES", "200"))  # برای هر کانال
OUTPUT_FILE = "raw_configs.json"
PERSONAL_OUTPUT_FILE = "personal_configs.json"
REQUEST_TIMEOUT = 20
MAX_PAGES = 30  # سقف ایمنی (هر صفحه ~۲۰ پیام)
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}
# =====================================================

CONFIG_PATTERNS = [
    r"vless://[^\s<\"']+",
    r"vmess://[^\s<\"']+",
    r"ss://[^\s<\"']+",
    r"trojan://[^\s<\"']+",
    r"hysteria2://[^\s<\"']+",
    r"hy2://[^\s<\"']+",
    r"tuic://[^\s<\"']+",
]

COMBINED_PATTERN = re.compile("|".join(CONFIG_PATTERNS), re.IGNORECASE)


def extract_configs(text: str) -> list[str]:
    if not text:
        return []
    matches = COMBINED_PATTERN.findall(text)
    return [m.strip().rstrip(".,;!])}'\"") for m in matches]


def parse_page(html: str) -> tuple[list[str], int | None, int]:
    """
    یک صفحه‌ی t.me/s رو پارس می‌کنه.
    خروجی: (کانفیگ‌ها، کوچک‌ترین message id برای صفحه‌ی بعد، تعداد پیام‌ها)
    """
    soup = BeautifulSoup(html, "html.parser")
    configs: list[str] = []
    ids: list[int] = []

    for msg in soup.select("div.tgme_widget_message[data-post]"):
        try:
            ids.append(int(msg["data-post"].rsplit("/", 1)[-1]))
        except (ValueError, KeyError):
            pass

        text_div = msg.select_one("div.tgme_widget_message_text")
        if text_div is None:
            continue
        # <br> ها رو به خط جدید تبدیل می‌کنیم تا کانفیگ‌های پشت‌سرهم به هم نچسبن
        for br in text_div.find_all("br"):
            br.replace_with("\n")
        configs.extend(extract_configs(text_div.get_text("\n")))
        # بعضی وقت‌ها لینک داخل href هست و متن نمایشی کوتاه شده
        for a in text_div.find_all("a", href=True):
            configs.extend(extract_configs(a["href"]))

    return configs, (min(ids) if ids else None), len(ids)


async def scrape_channel(session: ClientSession, channel: str, limit: int) -> set[str]:
    found: set[str] = set()
    before: int | None = None
    seen_messages = 0

    for _ in range(MAX_PAGES):
        url = f"https://t.me/s/{channel}" + (f"?before={before}" if before else "")
        try:
            async with session.get(url) as resp:
                if resp.status != 200:
                    print(f"  ⚠️ {channel}: HTTP {resp.status}")
                    break
                html = await resp.text()
        except Exception as e:
            print(f"  ⚠️ {channel}: خطای شبکه ({e})")
            break

        configs, min_id, count = parse_page(html)
        if count == 0:
            if before is None:
                print(f"  ⚠️ {channel}: پیامی پیدا نشد (کانال خصوصیه یا preview غیرفعاله؟)")
            break

        found.update(configs)
        seen_messages += count
        if seen_messages >= limit or not min_id or min_id <= 1:
            break
        before = min_id
        await asyncio.sleep(0.7)  # مودب بودن با t.me

    print(f"  📥 {channel}: {seen_messages} پیام → {len(found)} کانفیگ یکتا")
    return found


async def main():
    timeout = ClientTimeout(total=REQUEST_TIMEOUT)
    async with ClientSession(headers=HEADERS, timeout=timeout) as session:
        print(f"در حال خواندن {len(CHANNELS)} کانال عمومی: {', '.join(CHANNELS)}")
        all_configs: set[str] = set()
        for ch in CHANNELS:
            all_configs |= await scrape_channel(session, ch, LIMIT_MESSAGES)

        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(sorted(all_configs), f, ensure_ascii=False, indent=2)
        print(f"\nتعداد {len(all_configs)} کانفیگ یکتا در '{OUTPUT_FILE}' ذخیره شد.")

        personal: set[str] = set()
        if PERSONAL_CHANNEL:
            print(f"\nخواندن کانال شخصی: {PERSONAL_CHANNEL}")
            personal = await scrape_channel(session, PERSONAL_CHANNEL, LIMIT_MESSAGES)
        with open(PERSONAL_OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(sorted(personal), f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    asyncio.run(main())
