/**
 * telegram_webhook.js — جایگزین custom_listener.py (روی Cloudflare Workers، رایگان)
 * ============================================================================
 * custom_listener.py باید ۲۴ ساعته به تلگرام وصل می‌موند. این Worker فقط وقتی
 * پیام جدیدی توی کانال شخصی‌ت پست بشه بیدار می‌شه (Telegram webhook)، لینک‌ها رو
 * استخراج می‌کنه و با repository_dispatch بلافاصله workflow گیت‌هاب رو اجرا می‌کنه.
 *
 * متغیرهای لازم (Settings → Variables and Secrets در Cloudflare):
 *   GITHUB_TOKEN       (secret) توکن fine-grained با دسترسی Contents: Read & Write روی همین repo
 *   GITHUB_REPO        مثلا "myuser/veloce-vps"
 *   TG_SECRET          (secret) یک رشته‌ی تصادفی؛ همون رو موقع setWebhook به تلگرام می‌دی
 *   ALLOWED_CHAT_ID    آیدی عددی کانال شخصی (مثلا -1001234567890)
 *
 * بات رو ادمین کانال شخصی کن تا channel_post ها بهش برسه.
 */

const CONFIG_RE =
  /(?:vless|vmess|ss|trojan|hysteria2|hy2|tuic):\/\/[^\s<"']+/gi;

function extractConfigs(text) {
  if (!text) return [];
  const found = text.match(CONFIG_RE) || [];
  return [...new Set(found.map((m) => m.trim().replace(/[.,;!\])}'"]+$/, "")))];
}

export default {
  async fetch(request, env) {
    if (request.method !== "POST") {
      return new Response("Veloce webhook is alive", { status: 200 });
    }

    // فقط درخواست‌هایی که واقعاً از تلگرام اومدن
    if (request.headers.get("X-Telegram-Bot-Api-Secret-Token") !== env.TG_SECRET) {
      return new Response("forbidden", { status: 403 });
    }

    let update;
    try {
      update = await request.json();
    } catch {
      return new Response("bad request", { status: 400 });
    }

    const msg =
      update.channel_post ||
      update.edited_channel_post ||
      update.message ||
      update.edited_message;
    if (!msg || String(msg.chat?.id) !== String(env.ALLOWED_CHAT_ID)) {
      return new Response("ignored", { status: 200 });
    }

    // متن + لینک‌هایی که داخل entityها (text_link) پنهان شدن
    let text = msg.text || msg.caption || "";
    for (const e of msg.entities || msg.caption_entities || []) {
      if (e.type === "text_link" && e.url) text += "\n" + e.url;
    }
    const configs = extractConfigs(text).slice(0, 100);
    if (configs.length === 0) {
      return new Response("no configs", { status: 200 });
    }

    const res = await fetch(
      `https://api.github.com/repos/${env.GITHUB_REPO}/dispatches`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${env.GITHUB_TOKEN}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
          "User-Agent": "veloce-telegram-webhook",
        },
        body: JSON.stringify({
          event_type: "new-config",
          client_payload: { configs },
        }),
      }
    );

    // همیشه 200 به تلگرام برمی‌گردونیم تا پیام رو بی‌نهایت retry نکنه
    const note = res.ok ? `dispatched ${configs.length}` : `github error ${res.status}`;
    return new Response(note, { status: 200 });
  },
};
