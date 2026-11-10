import ipaddress
import math
import re
import socket
import time
from urllib.parse import urlparse, urljoin

import requests

from . import dl_model

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "s.id", "rb.gy", "bom.so"}
BAD_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "work",
            "support", "zip", "mov", "icu", "buzz", "monster", "loan"}
KEYWORDS = ["login", "signin", "verify", "update", "secure", "account", "banking", "confirm",
            "password", "otp", "wallet", "bonus", "gift", "xacminh", "dangnhap", "khoataikhoan"]
BRANDS = ["paypal", "vietcombank", "techcombank", "bidv", "vietinbank", "mbbank", "agribank",
          "momo", "zalopay", "shopee", "facebook", "google", "apple", "microsoft", "netflix"]


def normalize(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def _is_public_host(host: str) -> bool:
    """Chống SSRF: chỉ cho server truy cập địa chỉ public."""
    try:
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False
        return True
    except Exception:
        return False


def unshorten(url: str, max_hops: int = 6):
    """Smart Unshortener: lần theo chuỗi redirect của link rút gọn, trả (url_cuối, chuỗi)."""
    chain, current = [url], url
    for _ in range(max_hops):
        host = (urlparse(current).hostname or "").lower()
        if host not in SHORTENERS:  # chỉ mở rộng link rút gọn, không truy cập site lạ
            break
        if not _is_public_host(host):
            break
        try:
            r = requests.head(current, allow_redirects=False, timeout=4,
                              headers={"User-Agent": "Mozilla/5.0 MobilePhishGuard"})
        except requests.RequestException:
            break
        loc = r.headers.get("Location")
        if r.status_code in (301, 302, 303, 307, 308) and loc:
            current = urljoin(current, loc)
            chain.append(current)
        else:
            break
    return current, chain


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


def rule_analysis(url: str):
    """Explainable AI: mỗi luật trả về (điểm rủi ro, lý do)."""
    p = urlparse(url)
    host = (p.hostname or "").lower()
    reasons = []

    def add(points, msg):
        reasons.append({"points": points, "message": msg})

    try:
        ipaddress.ip_address(host)
        add(30, "Dùng địa chỉ IP thay cho tên miền")
    except ValueError:
        pass
    if p.scheme != "https":
        add(10, "Không dùng HTTPS (kết nối không mã hóa)")
    if len(url) > 75:
        add(12, f"URL quá dài ({len(url)} ký tự) – thường dùng để che giấu tên miền thật")
    if "@" in url:
        add(20, "Chứa ký tự '@' – kỹ thuật đánh lừa trình duyệt về đích đến thật")
    if host.count(".") >= 4:
        add(15, f"Quá nhiều cấp subdomain ({host.count('.')} dấu chấm)")
    if host.count("-") >= 2:
        add(10, "Tên miền chứa nhiều dấu gạch ngang")
    if host.startswith("xn--") or ".xn--" in host:
        add(25, "Tên miền Punycode (xn--) – có thể là ký tự giả mạo (homograph)")
    elif any(ord(c) > 127 for c in host):
        add(25, "Tên miền chứa ký tự không phải ASCII – có thể giả mạo ký tự")
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in BAD_TLDS:
        add(15, f"Đuôi tên miền '.{tld}' thường bị lạm dụng cho lừa đảo")
    hits = [k for k in KEYWORDS if k in url.lower()]
    if hits:
        add(min(8 * len(hits), 20), "Chứa từ khóa nhạy cảm: " + ", ".join(hits[:4]))
    for b in BRANDS:
        legit = any(host == b + s or host.endswith("." + b + s) for s in (".com", ".com.vn", ".vn", ".net"))
        if b in host and not legit:
            add(30, f"Có dấu hiệu giả mạo thương hiệu '{b}' (tên miền không phải của {b})")
            break
    if sum(c.isdigit() for c in host) >= 5:
        add(10, "Tên miền chứa nhiều chữ số")
    if _entropy(host) > 3.8 and len(host) > 15:
        add(10, "Tên miền trông ngẫu nhiên (entropy cao)")
    if p.port and p.port not in (80, 443):
        add(8, f"Dùng cổng bất thường ({p.port})")
    if host in SHORTENERS:
        add(10, "Là link rút gọn – đích đến thật bị ẩn")
    return reasons


TRUSTED = {
    "youtube.com": "YouTube", "google.com": "Google", "facebook.com": "Facebook",
    "microsoft.com": "Microsoft", "apple.com": "Apple", "github.com": "GitHub",
    "wikipedia.org": "Wikipedia", "zalo.me": "Zalo", "vietcombank.com.vn": "Vietcombank",
    "techcombank.com": "Techcombank", "bidv.com.vn": "BIDV", "momo.vn": "MoMo",
    "shopee.vn": "Shopee", "paypal.com": "PayPal", "netflix.com": "Netflix",
}


def trusted_name(host: str):
    for d, n in TRUSTED.items():
        if host == d or host.endswith("." + d):
            return n
    return None


def indicators(url: str, chain: list):
    """Bảng chỉ số trích xuất – luôn hiển thị đủ để minh họa Explainable AI.
    status: ok (an toàn) | warn (lưu ý) | bad (nguy hiểm) | info (trung tính)"""
    p = urlparse(url)
    host = (p.hostname or "").lower()
    rows = []

    def add(name, status, value):
        rows.append({"name": name, "status": status, "value": value})

    add("HTTPS", "ok" if p.scheme == "https" else "bad",
        "Hợp lệ" if p.scheme == "https" else "Không dùng HTTPS")
    add("Độ dài URL", "ok" if len(url) <= 75 else "warn",
        f"Bình thường ({len(url)} ký tự)" if len(url) <= 75 else f"Quá dài ({len(url)} ký tự)")
    t = trusted_name(host)
    add("Tên miền", "ok" if t else "info", f"{t} Official" if t else "Chưa có trong danh sách tin cậy")
    try:
        ipaddress.ip_address(host)
        add("Dạng địa chỉ", "bad", "Dùng địa chỉ IP")
    except ValueError:
        add("Dạng địa chỉ", "ok", "Tên miền thông thường")
    subs = max(0, host.count(".") - 1)
    add("Số subdomain", "ok" if subs <= 2 else "warn", f"{subs} cấp")
    odd = []
    if "@" in url:
        odd.append("ký tự @")
    if "xn--" in host:
        odd.append("Punycode")
    if any(ord(c) > 127 for c in host):
        odd.append("ký tự ngoài ASCII")
    add("Ký tự lạ", "bad" if odd else "ok", "Có: " + ", ".join(odd) if odd else "Không")
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    add("Đuôi tên miền", "warn" if tld in BAD_TLDS else "ok", f".{tld}" + (" (hay bị lạm dụng)" if tld in BAD_TLDS else ""))
    hits = [k for k in KEYWORDS if k in url.lower()]
    add("Từ khóa nhạy cảm", "warn" if hits else "ok", ", ".join(hits[:4]) if hits else "Không")
    fake = None
    for b in BRANDS:
        legit = any(host == b + s or host.endswith("." + b + s) for s in (".com", ".com.vn", ".vn", ".net"))
        if b in host and not legit:
            fake = b
            break
    add("Giả mạo thương hiệu", "bad" if fake else "ok", f"Nghi giả mạo '{fake}'" if fake else "Không phát hiện")
    hops = len(chain) - 1
    add("Link rút gọn / chuyển hướng", "warn" if hops > 0 else "ok",
        f"Đã giải mã qua {hops} lần chuyển hướng" if hops > 0 else "Không")
    return rows


def analyze(raw_url: str) -> dict:
    url = normalize(raw_url)
    final_url, chain = unshorten(url)

    reasons = rule_analysis(final_url)
    if len(chain) > 2:
        reasons.append({"points": 10, "message": f"Chuyển hướng qua {len(chain) - 1} lần"})
    rule_score = min(100, sum(r["points"] for r in reasons))

    # --- Deep Learning: Char-CNN ---
    dl_prob = dl_model.predict(final_url)
    if dl_prob is None:
        risk, engine = rule_score, "Rule-based Engine"
    else:
        risk = round(0.5 * dl_prob * 100 + 0.5 * rule_score)
        engine = "Hybrid Engine (Char-CNN + Rules)"
        if dl_prob >= 0.5:
            reasons.append({"points": round(dl_prob * 100 / 5), "message":
                            f"Mô hình Deep Learning nhận thấy chuỗi URL có cấu trúc giống trang lừa đảo ({dl_prob:.0%})"})
    if trusted_name((urlparse(final_url).hostname or "").lower()):
        risk = min(risk, 10)  # tên miền chính thức đã biết

    verdict = "safe" if risk < 30 else "suspicious" if risk < 60 else "phishing"
    return {
        "input": raw_url, "final_url": final_url, "chain": chain,
        "risk_score": risk, "verdict": verdict, "engine": engine,
        "dl_active": dl_prob is not None,
        "dl_prob": None if dl_prob is None else round(dl_prob * 100, 1),
        "reasons": sorted(reasons, key=lambda r: -r["points"]),
        "indicators": indicators(final_url, chain),
    }
