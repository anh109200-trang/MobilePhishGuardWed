"""Sinh dữ liệu URL mô phỏng (an toàn / phishing) để huấn luyện thử Char-CNN
khi chưa có dataset thật. Khi làm báo cáo, nên thay bằng dataset thật (xem train_cnn.py)."""
import random
import string

SAFE_DOMAINS = [
    "youtube.com", "google.com", "facebook.com", "wikipedia.org", "github.com", "microsoft.com",
    "apple.com", "amazon.com", "netflix.com", "linkedin.com", "twitter.com", "instagram.com",
    "zalo.me", "shopee.vn", "lazada.vn", "tiki.vn", "vnexpress.net", "tuoitre.vn", "thanhnien.vn",
    "dantri.com.vn", "zingmp3.vn", "vietcombank.com.vn", "techcombank.com", "bidv.com.vn",
    "vietinbank.vn", "mbbank.com.vn", "agribank.com.vn", "momo.vn", "zalopay.vn", "paypal.com",
    "stackoverflow.com", "reddit.com", "medium.com", "dropbox.com", "adobe.com", "spotify.com",
    "tiktok.com", "bbc.com", "cnn.com", "nytimes.com", "coursera.org", "udemy.com", "python.org",
    "djangoproject.com", "mozilla.org", "cloudflare.com", "gov.vn", "hcmus.edu.vn", "vnu.edu.vn",
    "ebay.com", "booking.com", "grab.com", "traveloka.com", "fpt.vn", "viettel.vn", "vnpt.vn",
]
SAFE_SUBS = ["www", "www", "www", "m", "accounts", "mail", "docs", "support", "help", "news", "login"]
WORDS = ["home", "about", "news", "products", "contact", "search", "watch", "article", "category",
         "profile", "settings", "help", "download", "blog", "events", "pricing", "video", "shop",
         "item", "post", "user", "login", "signin", "account", "payment", "order", "update", "verify"]
BRANDS = ["paypal", "vietcombank", "techcombank", "bidv", "vietinbank", "mbbank", "agribank", "momo",
          "zalopay", "shopee", "facebook", "google", "apple", "microsoft", "netflix", "zalo", "amazon"]
KW = ["login", "signin", "verify", "update", "secure", "account", "confirm", "password", "otp",
      "wallet", "bonus", "gift", "banking", "xacminh", "dangnhap", "nhanqua", "khoataikhoan", "support"]
BAD_TLDS = ["xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "icu", "buzz", "work", "support",
            "loan", "monster", "site", "online", "info", "cc", "ru", "live"]
MIX_TLDS = ["com", "net", "org", "info", "co", "vn", "online", "site"]


def _rs(n, alphabet=string.ascii_lowercase + string.digits):
    return "".join(random.choice(alphabet) for _ in range(n))


def _path(max_parts=3):
    parts = [random.choice(WORDS) for _ in range(random.randint(0, max_parts))]
    p = "/" + "/".join(parts) if parts else ""
    r = random.random()
    if r < 0.25:
        p += f"?id={random.randint(1, 99999)}"
    elif r < 0.35:
        p += f"?v={_rs(11, string.ascii_letters + string.digits)}"
    elif r < 0.40:
        p += f"/{random.randint(2015, 2026)}/{random.randint(1, 12)}/{_rs(8)}"
    return p


def safe_url():
    d = random.choice(SAFE_DOMAINS)
    host = d if random.random() < 0.4 else f"{random.choice(SAFE_SUBS)}.{d}"
    scheme = "https" if random.random() < 0.9 else "http"
    return f"{scheme}://{host}{_path()}"


def phish_url():
    b, k, t = random.choice(BRANDS), random.choice(KW), random.choice(BAD_TLDS)
    scheme = "http" if random.random() < 0.6 else "https"
    ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
    legit = random.choice(SAFE_DOMAINS)
    tail = random.choice([f"/{k}", f"/{k}/{b}.php", f"/{b}/{k}?id={_rs(10)}", f"/{_rs(8)}/{k}.html", _path()])
    kind = random.randint(0, 9)
    if kind == 0:
        return f"{scheme}://{b}-{k}.{t}{tail}"
    if kind == 1:
        return f"http://{ip}{tail}"
    if kind == 2:
        return f"{scheme}://{b}.{k}.{_rs(random.randint(5, 9))}.{random.choice(MIX_TLDS)}{tail}"
    if kind == 3:
        return f"{scheme}://{legit}.{k}-{_rs(5)}.{t}{tail}"
    if kind == 4:
        return f"{scheme}://{_rs(random.randint(8, 16))}.{t}{tail}?token={_rs(24)}&session={_rs(16)}"
    if kind == 5:
        return f"{scheme}://{legit}@{_rs(8)}.{t}{tail}"
    if kind == 6:
        return f"https://xn--{_rs(6)}-{b}.{random.choice(MIX_TLDS)}/{k}"
    if kind == 7:
        return f"{scheme}://{b}-{k}-{_rs(4)}.{random.choice(MIX_TLDS)}{tail}"
    if kind == 8:
        return f"{scheme}://secure-{b}{random.randint(1, 99)}.{k}.{t}{tail}"
    return f"{scheme}://www.{b}{k}.{random.choice(MIX_TLDS)}.{_rs(6)}.{t}{tail}"


def generate(n_per_class=12000, seed=42):
    random.seed(seed)
    urls = [safe_url() for _ in range(n_per_class)] + [phish_url() for _ in range(n_per_class)]
    labels = [0] * n_per_class + [1] * n_per_class
    idx = list(range(len(urls)))
    random.shuffle(idx)
    return [urls[i] for i in idx], [labels[i] for i in idx]
