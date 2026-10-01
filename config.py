"""
ماژول جامع مدیریت پارسرها و تنظیمات هسته Xray (config.py)
پشتیبانی از پروتکل‌ها: VLESS, VMess, Trojan, Shadowsocks, Hysteria2
پشتیبانی از بسترها (Transports): TCP, WebSocket, gRPC, xhttp/splithttp, HTTPUpgrade, h2, mKCP, QUIC
پشتیبانی از امنیت: REALITY, TLS, uTLS Fingerprint, XTLS-Vision Flow
"""
import base64
import hashlib
import json
import os
import sys
from urllib.parse import parse_qs, urlparse

XRAY_BIN = "xray.exe" if sys.platform == "win32" else "xray"

if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.getcwd()

# روی GitHub Actions مسیر xray با متغیر محیطی XRAY_PATH قابل override هست
XRAY_PATH = os.environ.get("XRAY_PATH") or os.path.join(BASE_DIR, XRAY_BIN)
LOCAL_SOCKS_PORT = 27080

# مسیر فایل کانفیگ‌های معتبر — هم main.py (لوکال) هم public_api.py (VPS)
# از همین مسیر واحد استفاده می‌کنن تا هیچ‌وقت دچار ناهماهنگی نشن.
DATA_FILE = os.path.join(BASE_DIR, "valid_configs.json")

# آدرس فایل استاتیک لیست کانفیگ‌ها (جایگزین public_api.py روی VPS).
# بعد از اولین دیپلوی، USERNAME و REPO رو با مقدار واقعی جایگزین کن
# یا متغیر محیطی VELOCE_CENTRAL_API_URL رو ست کن.
CENTRAL_API_URL = os.environ.get(
    "VELOCE_CENTRAL_API_URL",
    "https://USERNAME.github.io/REPO/api/v1/candidates.json",
)


def stable_config_id(uri: str) -> str:
    """تولید شناسه پایدار SHA-1 بر اساس متن لینک کانفیگ"""
    return hashlib.sha1(uri.encode("utf-8")).hexdigest()[:12]


def _build_stream_settings(network: str, security: str, params: dict) -> dict:
    """
    موتور یکپارچه ساخت streamSettings برای تمام پروتکل‌های انتقال و امنیت
    """
    stream = {
        "network": network,
        "security": security
    }

    # ──────────────── 1. لایه‌های امنیتی (Security) ────────────────
    if security == "reality":
        pbk = params.get("pbk") or params.get("publicKey") or ""
        if not pbk:
            return {}  # بدون کلید عمومی REALITY امکان استارت وجود ندارد

        stream["realitySettings"] = {
            "show": False,
            "fingerprint": params.get("fp") or params.get("fingerprint") or "chrome",
            "serverName": params.get("sni") or params.get("serverName") or "",
            "publicKey": pbk,
            "shortId": params.get("sid") or params.get("shortId") or "",
            "spiderX": params.get("spx") or params.get("spiderX") or "",
        }

    elif security == "tls":
        alpn_raw = params.get("alpn")
        if isinstance(alpn_raw, str):
            alpn_list = [a.strip() for a in alpn_raw.split(",") if a.strip()]
        elif isinstance(alpn_raw, list):
            alpn_list = alpn_raw
        else:
            alpn_list = ["h2", "http/1.1"]

        allow_insecure = str(params.get("allowInsecure") or params.get("insecure") or "0") in ("1", "true")

        stream["tlsSettings"] = {
            "serverName": params.get("sni") or params.get("host") or "",
            "allowInsecure": allow_insecure,
            "alpn": alpn_list,
            "fingerprint": params.get("fp") or params.get("fingerprint") or "chrome"
        }

    # ──────────────── 2. بسترهای انتقال (Network / Transport) ────────────────
    if network == "ws":
        headers = {}
        host = params.get("host") or ""
        if host:
            headers["Host"] = host

        stream["wsSettings"] = {
            "path": params.get("path") or "/",
            "headers": headers
        }

    elif network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": params.get("serviceName") or params.get("service_name") or "",
            "multiMode": str(params.get("mode", "")).lower() == "multi"
        }

    elif network in ("xhttp", "splithttp"):
        headers = {}
        host = params.get("host") or ""
        if host:
            headers["Host"] = host

        stream["xhttpSettings"] = {
            "path": params.get("path") or "/",
            "host": host,
            "mode": params.get("mode") or "auto",
            "headers": headers
        }

    elif network == "httpupgrade":
        headers = {}
        host = params.get("host") or ""
        if host:
            headers["Host"] = host

        stream["httpupgradeSettings"] = {
            "path": params.get("path") or "/",
            "host": host,
            "headers": headers
        }

    elif network in ("h2", "http"):
        host = params.get("host") or ""
        stream["httpSettings"] = {
            "path": params.get("path") or "/",
            "host": [host] if host else []
        }

    elif network in ("kcp", "mkcp"):
        stream["kcpSettings"] = {
            "header": {
                "type": params.get("headerType") or params.get("type") or "none"
            },
            "seed": params.get("seed") or params.get("path") or ""
        }

    elif network == "quic":
        stream["quicSettings"] = {
            "security": params.get("quicSecurity") or "none",
            "key": params.get("key") or "",
            "header": {
                "type": params.get("headerType") or "none"
            }
        }

    return stream


def parse_vless(uri: str) -> tuple[dict | None, str]:
    """پارس جامع لینک‌های vless://"""
    try:
        parsed = urlparse(uri)
        qs = parse_qs(parsed.query)
        flat_qs = {k: v[0] for k, v in qs.items() if v}

        address = parsed.hostname
        if not address:
            return None, "tcp"

        port = parsed.port or 443
        uuid = parsed.username or ""

        network = flat_qs.get("type", "tcp").lower()
        security = flat_qs.get("security", "none").lower()
        flow = flat_qs.get("flow", "")

        user_dict = {
            "id": uuid,
            "encryption": flat_qs.get("encryption", "none")
        }
        if flow:
            user_dict["flow"] = flow

        stream_settings = _build_stream_settings(network, security, flat_qs)
        if security == "reality" and not stream_settings.get("realitySettings"):
            return None, "tcp"

        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": address,
                    "port": port,
                    "users": [user_dict]
                }]
            },
            "streamSettings": stream_settings
        }
        return outbound, network
    except Exception:
        return None, "tcp"


def parse_vmess(uri: str) -> tuple[dict | None, str]:
    """پارس جامع لینک‌های vmess://"""
    try:
        b64 = uri.replace("vmess://", "")
        b64 += "=" * (-len(b64) % 4)
        data = json.loads(base64.b64decode(b64).decode("utf-8"))

        address = data.get("add")
        if not address:
            return None, "tcp"

        port = int(data.get("port", 443))
        network = str(data.get("net", "tcp")).lower()
        sec_raw = str(data.get("tls", "none")).lower()
        security = "tls" if sec_raw in ("tls", "1", "true") else "none"

        params = {
            "sni": data.get("sni") or data.get("host") or "",
            "host": data.get("host") or "",
            "path": data.get("path") or "/",
            "fp": data.get("fp") or "chrome",
            "alpn": data.get("alpn") or "h2,http/1.1",
            "serviceName": data.get("path") or data.get("serviceName") or "",
            "headerType": data.get("type") or "none",
        }

        stream_settings = _build_stream_settings(network, security, params)

        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": address,
                    "port": port,
                    "users": [{
                        "id": str(data.get("id", "")),
                        "alterId": int(data.get("aid", 0)),
                        "security": str(data.get("scy", "auto")),
                    }]
                }]
            },
            "streamSettings": stream_settings
        }
        return outbound, network
    except Exception:
        return None, "tcp"


def parse_trojan(uri: str) -> tuple[dict | None, str]:
    """پارس جامع لینک‌های trojan://"""
    try:
        parsed = urlparse(uri)
        qs = parse_qs(parsed.query)
        flat_qs = {k: v[0] for k, v in qs.items() if v}

        address = parsed.hostname
        if not address:
            return None, "tcp"

        port = parsed.port or 443
        password = parsed.username or ""

        network = flat_qs.get("type", "tcp").lower()
        security = flat_qs.get("security", "tls").lower()

        if not flat_qs.get("sni"):
            flat_qs["sni"] = address

        stream_settings = _build_stream_settings(network, security, flat_qs)

        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": address,
                    "port": port,
                    "password": password
                }]
            },
            "streamSettings": stream_settings
        }
        return outbound, network
    except Exception:
        return None, "tcp"


def parse_shadowsocks(uri: str) -> tuple[dict | None, str]:
    """پارس جامع لینک‌های ss:// (فرمت SIP002 و Legacy)"""
    try:
        body = uri[len("ss://"):]
        body = body.split("#", 1)[0].split("?", 1)[0]

        if "@" in body:
            userinfo, hostport = body.rsplit("@", 1)
            try:
                padded = userinfo + "=" * (-len(userinfo) % 4)
                decoded = base64.urlsafe_b64decode(padded).decode("utf-8")
                method, password = decoded.split(":", 1)
            except Exception:
                method, password = userinfo.split(":", 1)

            if ":" not in hostport:
                return None, "tcp"
            host, port_str = hostport.rsplit(":", 1)
            port = int(port_str)
        else:
            padded = body + "=" * (-len(body) % 4)
            decoded = base64.urlsafe_b64decode(padded).decode("utf-8")
            creds, hostport = decoded.rsplit("@", 1)
            method, password = creds.split(":", 1)
            host, port_str = hostport.rsplit(":", 1)
            port = int(port_str)

        outbound = {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": host,
                    "port": port,
                    "method": method,
                    "password": password,
                }]
            },
        }
        return outbound, "tcp"
    except Exception:
        return None, "tcp"


def parse_hysteria2(uri: str) -> tuple[dict | None, str]:
    """پارس جامع لینک‌های hysteria2:// و hy2://"""
    try:
        parsed = urlparse(uri)
        qs = parse_qs(parsed.query)
        flat_qs = {k: v[0] for k, v in qs.items() if v}

        address = parsed.hostname
        if not address:
            return None, "tcp"

        port = parsed.port or 443
        password = parsed.username or flat_qs.get("auth", "")

        sni = flat_qs.get("sni") or address
        insecure = flat_qs.get("insecure") in ("1", "true") or flat_qs.get("allowInsecure") in ("1", "true")

        outbound = {
            "protocol": "hysteria2",
            "settings": {
                "servers": [{
                    "address": address,
                    "port": port,
                    "password": password,
                }]
            },
            "streamSettings": {
                "network": "hysteria2",
                "security": "tls",
                "tlsSettings": {
                    "serverName": sni,
                    "allowInsecure": insecure,
                },
            },
        }

        obfs_type = flat_qs.get("obfs")
        obfs_password = flat_qs.get("obfs-password") or flat_qs.get("obfs_password")
        if obfs_type:
            outbound["streamSettings"]["hy2Settings"] = {
                "obfs": {
                    "type": obfs_type,
                    "password": obfs_password or ""
                }
            }

        return outbound, "hysteria2"
    except Exception:
        return None, "tcp"


def parse_uri(uri: str) -> tuple[dict | None, str]:
    """دیسپچر یکپارچه شناسایی پروتکل‌ها"""
    if uri.startswith("vless://"):
        return parse_vless(uri)
    if uri.startswith("vmess://"):
        return parse_vmess(uri)
    if uri.startswith("ss://"):
        return parse_shadowsocks(uri)
    if uri.startswith("trojan://"):
        return parse_trojan(uri)
    if uri.startswith("hysteria2://") or uri.startswith("hy2://"):
        return parse_hysteria2(uri)
    return None, "tcp"


def create_xray_config(uri: str, local_port: int, enable_adblock: bool = False) -> dict | None:
    outbound, _ = parse_uri(uri)
    if not outbound:
        return None

    outbound["tag"] = "proxy"
    
    # اضافه کردن Freedom برای هندل مستقیم و DNS داخلی
    direct_outbound = {"protocol": "freedom", "tag": "direct"}
    dns_outbound = {"protocol": "dns", "tag": "dns-out"}
    api_outbound = {"protocol": "freedom", "tag": "api"}
    
    outbounds = [outbound, direct_outbound, dns_outbound, api_outbound]

    inbound = {
        "port": local_port,
        "listen": "127.0.0.1",
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": True},
        "sniffing": {
            "enabled": True,
            "destOverride": ["http", "tls", "quic"],
            "routeOnly": False,
        },
    }

    # تعریف DNS داخلی Xray با قابلیت Fallback به DoH
    dns_config = {
        "servers": [
            "https://1.1.1.1/dns-query",
            "1.1.1.1",
            "8.8.8.8",
            "localhost",
        ]
    }

    rules = [
        {
            "type": "field",
            "inboundTag": ["api"],
            "outboundTag": "api",
        },
        {
            "type": "field",
            "port": 53,
            "network": "udp,tcp",
            "outboundTag": "dns-out",
        },
    ]

    if enable_adblock:
        outbounds.append({"protocol": "blackhole", "tag": "block"})
        rules.append({
            "type": "field",
            "domain": ["geosite:category-ads-all"],
            "outboundTag": "block",
        })

    config = {
        "log": {"loglevel": "none"},
        "dns": dns_config,
        "inbounds": [inbound],
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": rules,
        },
    }

    return config
