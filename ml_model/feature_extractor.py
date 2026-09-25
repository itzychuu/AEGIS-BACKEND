import re
from urllib.parse import urlparse
from typing import Dict, Any

import numpy as np
import pandas as pd
import tldextract

from .exceptions import InvalidURLError

WORDS = [
    "login", "signin", "sign-in", "verify", "verification",
    "secure", "account", "update", "confirm", "password",
    "credential", "wallet", "bank", "payment", "invoice",
    "recover", "unlock", "authorize", "authentication",
    "support", "alert", "billing", "security", "session",
    "validate", "activate", "claim"
]

SHORT = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
    "rebrand.ly",
    "tiny.cc"
}

TLDS = {
    "com", "org", "net", "edu", "gov", "io",
    "co", "ai", "dev", "app", "me", "info",
    "biz", "in", "uk", "de", "fr", "ca", "au"
}


def normalize_url(url: str) -> str:
    """Normalize input URL according to XGBoost V6 canonical standards."""
    if url is None or not isinstance(url, str):
        raise InvalidURLError(f"URL must be a non-empty string, got {type(url).__name__}")

    url = url.strip()
    if not url:
        raise InvalidURLError("URL string cannot be empty or whitespace-only")

    if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", url):
        url = "https://" + url

    url = url.lower()
    # Strip trailing slashes for canonical equivalence (matching prepare_data_v6 logic)
    if "://" in url:
        scheme, rest = url.split("://", 1)
        if rest and rest != "/":
            rest = rest.rstrip("/")
        url = f"{scheme}://{rest}"

    return url


def entropy(value: str) -> float:
    """Calculate Shannon entropy for a given string."""
    if not value:
        return 0.0

    _, counts = np.unique(list(value), return_counts=True)
    probabilities = counts / counts.sum()
    return float(-(probabilities * np.log2(probabilities)).sum())


def extract_features(url: str) -> Dict[str, Any]:
    """Extract full 51-feature dictionary matching V6 training pipeline logic."""
    normalized = normalize_url(url)
    x = normalized

    parsed = urlparse(x)
    try:
        hostname = (parsed.hostname or "").lower().strip(".")
    except Exception:
        hostname = ""

    path = parsed.path or ""
    query = parsed.query or ""
    full_url = x

    extracted = tldextract.extract(hostname)
    subdomain = extracted.subdomain.lower()
    domain = extracted.domain.lower()
    tld = extracted.suffix.lower()

    digs = sum(c.isdigit() for c in full_url)
    lets = sum(c.isalpha() for c in full_url)
    spec = sum(not c.isalnum() for c in full_url)

    words = sum(word in full_url for word in WORDS)
    is_ip = bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", hostname))

    try:
        has_port_val = int(parsed.port is not None) if parsed.port else 0
    except ValueError:
        has_port_val = 0

    path_segments = [s for s in path.split("/") if s]

    return {
        "url_length": len(x),
        "hostname_length": len(hostname),
        "registered_domain_length": len(domain),
        "subdomain_length": len(subdomain),
        "path_length": len(path),
        "query_length": len(query),
        "fragment_length": len(parsed.fragment or ""),
        "num_dots": full_url.count("."),
        "num_hyphens": full_url.count("-"),
        "num_underscores": full_url.count("_"),
        "num_slashes": full_url.count("/"),
        "num_question": full_url.count("?"),
        "num_equals": full_url.count("="),
        "num_ampersands": full_url.count("&"),
        "num_at": full_url.count("@"),
        "num_percent": full_url.count("%"),
        "num_colons": full_url.count(":"),
        "num_semicolon": full_url.count(";"),
        "num_digits": digs,
        "num_letters": lets,
        "num_special": spec,
        "digit_ratio": digs / max(len(full_url), 1),
        "letter_ratio": lets / max(len(full_url), 1),
        "special_ratio": spec / max(len(full_url), 1),
        "entropy": entropy(full_url),
        "host_entropy": entropy(hostname),
        "registered_entropy": entropy(domain),
        "path_entropy": entropy(path),
        "num_subdomains": len([s for s in subdomain.split(".") if s]),
        "has_www": int(hostname.startswith("www.")),
        "has_https": int(parsed.scheme == "https"),
        "has_http": int(parsed.scheme == "http"),
        "has_ip_host": int(is_ip),
        "has_port": has_port_val,
        "has_punycode": int("xn--" in hostname),
        "has_encoded_chars": int("%" in full_url),
        "has_double_slash_path": int("//" in path),
        "has_at_symbol": int("@" in full_url),
        "is_shortener": int(hostname in SHORT),
        "suspicious_word_count": words,
        "has_suspicious_word": int(words > 0),
        "tld_length": len(tld),
        "tld_is_common": int(tld in TLDS),
        "host_digit_ratio": sum(c.isdigit() for c in hostname) / max(len(hostname), 1),
        "host_hyphen_ratio": hostname.count("-") / max(len(hostname), 1),
        "path_digit_ratio": sum(c.isdigit() for c in path) / max(len(path), 1),
        "query_parameter_count": query.count("&") + (1 if query else 0),
        "path_segment_count": len(path_segments),
        "max_path_segment_length": max([len(s) for s in path_segments] or [0]),
        "hex_like_token_count": len(re.findall(r"[0-9a-f]{8,}", full_url)),
        "repeated_separator_count": len(re.findall(r"([._-])\1+", full_url)),
    }


def feature_frame(url: str) -> pd.DataFrame:
    """Extract features for a URL and return a clean single-row pandas DataFrame."""
    features = extract_features(url)
    frame = pd.DataFrame([features])
    return frame.replace([np.inf, -np.inf], 0).fillna(0)