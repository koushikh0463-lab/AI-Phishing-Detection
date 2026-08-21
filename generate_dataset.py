"""
generate_dataset.py
--------------------
Generates a synthetic labeled dataset of URLs for training the phishing
detection model. This is meant as a STARTER dataset so the whole pipeline
runs end-to-end immediately.

For a real academic/production project, replace dataset/phishing.csv with a
real-world dataset (e.g. a public phishing-URL dataset from Kaggle/PhishTank/
UCI) that has the same two columns: url,label  (0 = legitimate, 1 = phishing)
"""

import random
import csv

random.seed(42)

# ---------------------------------------------------------------------
# 1. Legitimate URLs (real, well-known domains, varied paths)
# ---------------------------------------------------------------------
legit_domains = [
    "google.com", "github.com", "wikipedia.org", "amazon.com", "microsoft.com",
    "apple.com", "nytimes.com", "bbc.com", "linkedin.com", "stackoverflow.com",
    "reddit.com", "python.org", "mozilla.org", "cloudflare.com", "netflix.com",
    "spotify.com", "adobe.com", "dropbox.com", "salesforce.com", "wordpress.com",
    "medium.com", "quora.com", "who.int", "un.org", "harvard.edu", "mit.edu",
    "irs.gov", "usa.gov", "nasa.gov", "ibm.com", "oracle.com", "intel.com",
    "samsung.com", "dell.com", "hp.com", "cisco.com", "paypal.com", "ebay.com",
    "twitter.com", "facebook.com", "instagram.com", "youtube.com", "yahoo.com",
    "bing.com", "duckduckgo.com", "wix.com", "shopify.com", "zoom.us",
    "slack.com", "atlassian.com", "digitalocean.com",
]

legit_paths = [
    "", "/", "/about", "/products", "/login", "/account", "/help", "/support",
    "/blog/2024/updates", "/docs/api/v2", "/search?q=example", "/user/profile",
    "/contact-us", "/careers", "/pricing", "/news/latest-release",
    "/settings/security", "/dashboard", "/checkout/cart", "/terms-of-service",
]

legit_urls = []
for domain in legit_domains:
    for _ in range(6):
        path = random.choice(legit_paths)
        scheme = "https"
        sub = random.choice(["", "www.", "www.", "docs.", "help."])
        legit_urls.append(f"{scheme}://{sub}{domain}{path}")

# de-dupe
legit_urls = list(dict.fromkeys(legit_urls))

# ---------------------------------------------------------------------
# 2. Synthetic phishing-style URLs (pattern-based, not real active sites)
#    These emulate well-documented phishing URL characteristics:
#    brand-lookalike subdomains, suspicious keywords, IP hosts, long
#    hyphenated strings, odd TLDs, no HTTPS, @ symbol tricks, etc.
# ---------------------------------------------------------------------
brands = ["paypal", "amazon", "apple", "microsoft", "netflix", "bankofamerica",
          "wellsfargo", "chase", "google", "facebook", "instagram", "irs",
          "dhl", "fedex", "usps", "outlook", "office365", "icloud"]

suspicious_keywords = ["login", "verify", "secure", "account", "update",
                        "confirm", "signin", "password", "reset", "billing",
                        "support", "security-alert", "unlock"]

odd_tlds = [".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".click", ".gq", ".info"]

random_suffixes = ["1234", "id29381", "auth7", "x9k2", "verify01", "sec2024",
                    "user882", "acct331", "temp29", "check77"]

def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

phishing_urls = []

# Pattern A: brand + suspicious keyword in a lookalike domain, odd TLD, http
for brand in brands:
    for _ in range(4):
        kw = random.choice(suspicious_keywords)
        suffix = random.choice(random_suffixes)
        tld = random.choice(odd_tlds)
        scheme = random.choice(["http", "http", "https"])
        pattern = random.choice([
            f"{scheme}://{brand}-{kw}-{suffix}{tld}/{kw}",
            f"{scheme}://{kw}.{brand}-{suffix}{tld}/",
            f"{scheme}://{brand}{kw}{suffix}.{random.choice(['com','net'])}{tld[1:] and tld or ''}",
            f"{scheme}://secure-{brand}.{kw}-{suffix}{tld}",
        ])
        phishing_urls.append(pattern)

# Pattern B: raw IP address host (classic phishing red flag)
for _ in range(30):
    kw = random.choice(suspicious_keywords)
    ip = random_ip()
    phishing_urls.append(f"http://{ip}/{kw}/{random.choice(brands)}")

# Pattern C: '@' trick — text before @ looks like the real domain
for _ in range(20):
    brand = random.choice(brands)
    fake_host = f"{random.choice(suspicious_keywords)}-{random.choice(random_suffixes)}.com"
    phishing_urls.append(f"http://{brand}.com@{fake_host}/{random.choice(suspicious_keywords)}")

# Pattern D: extremely long, hyphenated, multi-subdomain URLs
for _ in range(25):
    brand = random.choice(brands)
    parts = [random.choice(suspicious_keywords) for _ in range(4)]
    long_domain = "-".join(parts) + "-" + random.choice(random_suffixes)
    tld = random.choice(odd_tlds)
    phishing_urls.append(f"http://{brand}.{long_domain}{tld}/{'/'.join(parts[:2])}")

phishing_urls = list(dict.fromkeys(phishing_urls))

# ---------------------------------------------------------------------
# 3. Write CSV
# ---------------------------------------------------------------------
rows = [(u, 0) for u in legit_urls] + [(u, 1) for u in phishing_urls]
random.shuffle(rows)

out_path = "dataset/phishing.csv"
with open(out_path, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["url", "label"])
    writer.writerows(rows)

print(f"Wrote {len(rows)} rows to {out_path}")
print(f"  Legitimate (0): {len(legit_urls)}")
print(f"  Phishing   (1): {len(phishing_urls)}")
