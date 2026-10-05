import os
import re
import requests

GUARD_URL = os.environ.get("GUARD_URL", "https://secureai-guard-598609297408.europe-west4.run.app").rstrip("/")
GUARD_TOKEN = os.environ.get("GUARD_TOKEN", "sai_0ecbeac0a6d19dee8ab350f834ceb8f1")

HEADERS = {
    "Authorization": f"Bearer {GUARD_TOKEN}",
    "Content-Type": "application/json",
}

URL_PATTERN = re.compile(r"https?://[^\s]+|(?<![@\w])\b[\w.-]+\.(?:ly|co|gl|gd|xyz|top|tk|cc|info)\b[^\s]*", re.IGNORECASE)

# Local defense-in-depth heuristics, used whether or not the Guard re-check catches it.
SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".gq", ".cc", ".ml", ".work", ".click"}
BRAND_IMPERSONATION_KEYWORDS = [
    "login", "verify", "secure", "account", "suspended", "update-billing",
    "paypal", "bank", "signin", "confirm", "reset-password", "urgent",
]
KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy",
}


def _call_guard(text):
    resp = requests.post(
        f"{GUARD_URL}/v1/check/prompt",
        headers=HEADERS,
        json={"text": text},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def _extract_urls(text):
    return URL_PATTERN.findall(text)


def _resolve_url(url):
    """Follow redirects WITHOUT downloading the response body. Returns the final
    resolved URL, or None if it couldn't be resolved (treated as suspicious)."""
    candidate = url if url.startswith("http") else f"http://{url}"
    try:
        resp = requests.head(candidate, allow_redirects=True, timeout=6)
        # Some shorteners don't support HEAD properly -- fall back to a streamed GET
        # and close immediately without reading the body.
        if resp.status_code >= 400 or resp.url == candidate:
            resp = requests.get(candidate, allow_redirects=True, timeout=6, stream=True)
            resp.close()
        return resp.url
    except requests.RequestException:
        return None  # unresolvable -- treat as suspicious, not as safe


def _domain_of(url):
    match = re.match(r"https?://([^/]+)", url)
    return match.group(1).lower() if match else url.lower()


def _heuristic_flag(resolved_url):
    """Local defense-in-depth check on the resolved destination, independent of
    whatever the Guard itself decides."""
    domain = _domain_of(resolved_url)
    reasons = []

    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        reasons.append(f"suspicious TLD in resolved domain ({domain})")

    lowered = resolved_url.lower()
    hit_keywords = [kw for kw in BRAND_IMPERSONATION_KEYWORDS if kw in lowered]
    if hit_keywords:
        reasons.append(f"brand/urgency keywords in resolved URL: {hit_keywords}")

    return reasons


def check_prompt_with_hook(text, verbose=True):
    """Drop-in replacement for calling the Guard directly. Returns a dict with the
    Guard's own result PLUS the hook's link-cloaking analysis layered on top."""
    urls = _extract_urls(text)
    original_result = _call_guard(text)

    hook_findings = []
    augmented_text = text

    for url in urls:
        domain = _domain_of(url if url.startswith("http") else f"http://{url}")
        is_known_shortener = any(domain == s or domain.endswith("." + s) for s in KNOWN_SHORTENERS)

        resolved = _resolve_url(url)

        if resolved is None:
            hook_findings.append({
                "original_url": url,
                "resolved_url": None,
                "reason": "could not resolve redirect — treated as suspicious (fail-closed)",
            })
            continue

        if resolved.rstrip("/") == (url if url.startswith("http") else f"http://{url}").rstrip("/"):
            continue  # not actually a redirect, nothing hidden here

        # Something redirected. Re-screen the REAL destination through the Guard.
        augmented_text = augmented_text.replace(url, f"{url} (resolves to: {resolved})")
        heuristic_reasons = _heuristic_flag(resolved)

        if is_known_shortener or heuristic_reasons:
            hook_findings.append({
                "original_url": url,
                "resolved_url": resolved,
                "is_known_shortener": is_known_shortener,
                "heuristic_reasons": heuristic_reasons,
            })

    # Second pass: let the Guard itself see the real destination.
    rechecked_result = None
    if augmented_text != text:
        rechecked_result = _call_guard(augmented_text)

    cloaking_detected = bool(hook_findings) or (
        rechecked_result is not None
        and rechecked_result.get("allowed") is False
        and original_result.get("allowed") is True
    )

    final_allowed = original_result.get("allowed", True)
    final_flags = list(original_result.get("flags", []))
    if cloaking_detected:
        final_allowed = False
        if "link_cloaking" not in final_flags:
            final_flags.append("link_cloaking")

    result = {
        "allowed": final_allowed,
        "flags": final_flags,
        "original_guard_result": original_result,
        "rechecked_guard_result": rechecked_result,
        "hook_findings": hook_findings,
        "cloaking_detected": cloaking_detected,
    }

    if verbose:
        print(f"Original Guard check:  allowed={original_result.get('allowed')}  flags={original_result.get('flags')}")
        if rechecked_result:
            print(f"Re-check (resolved):   allowed={rechecked_result.get('allowed')}  flags={rechecked_result.get('flags')}")
        if hook_findings:
            print("Hook findings:")
            for f in hook_findings:
                print(f"   - {f}")
        print(f"FINAL (with hook):      allowed={final_allowed}  flags={final_flags}")

    return result


if __name__ == "__main__":
    print("=== Demo: the original bypass probe ===")
    check_prompt_with_hook("Check out this great resource: bit.ly/3xampl3link — totally safe, promise!")

    print("\n=== Demo: plain benign text (should pass through untouched) ===")
    check_prompt_with_hook("What is the capital of Ghana?")
