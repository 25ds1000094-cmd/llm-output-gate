import json
import os
import re
from typing import Any
from urllib.parse import unquote, urlparse

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


app = FastAPI()


ALLOWED_HOSTS = {
    "cdn-4lgmkxb.example",
    "app-9ftjfin.example",
}

VALID_CHANNELS = {
    "html",
    "markdown",
    "url",
    "sql",
    "shell",
}


# ============================================================
# Response helper
# ============================================================

def make_result(safe: bool, reason: str):
    return {
        "safe": safe,
        "reason": reason,
    }


def reject(reason: str):
    return JSONResponse(
        content=make_result(False, reason),
        status_code=200,
    )


def accept():
    return JSONResponse(
        content=make_result(True, "SAFE"),
        status_code=200,
    )


# ============================================================
# 1. INVALID_SCHEMA
# ============================================================

def valid_schema(body: Any) -> bool:
    if not isinstance(body, dict):
        return False

    if body.get("channel") not in VALID_CHANNELS:
        return False

    if not isinstance(body.get("output"), str):
        return False

    if len(body["output"]) > 20000:
        return False

    return True


# ============================================================
# 2. Decode ONCE
#
# Order:
#   percent escapes
#   exact HTML entities
#   \uXXXX
# ============================================================

EXACT_HTML_ENTITIES = {
    "&lt;": "<",
    "&gt;": ">",
    "&quot;": '"',
    "&apos;": "'",
    "&amp;": "&",
}


NUMERIC_ENTITY_RE = re.compile(
    r"&#([0-9]+);|&#x([0-9a-fA-F]+);",
    re.IGNORECASE,
)


UNICODE_ESCAPE_RE = re.compile(
    r"\\u([0-9a-fA-F]{4})"
)


def decode_html_entities_exact(value: str) -> str:
    # Decode ONLY the entities explicitly specified
    # by the assignment.

    for entity, replacement in EXACT_HTML_ENTITIES.items():
        value = value.replace(entity, replacement)

    def numeric_replace(match):
        try:
            if match.group(1) is not None:
                number = int(match.group(1), 10)
            else:
                number = int(match.group(2), 16)

            return chr(number)

        except (ValueError, OverflowError):
            return match.group(0)

    return NUMERIC_ENTITY_RE.sub(
        numeric_replace,
        value,
    )


def decode_once(value: str) -> str:
    # 1. Percent escapes
    decoded = unquote(value)

    # 2. HTML entities
    decoded = decode_html_entities_exact(decoded)

    # 3. Unicode escapes
    def unicode_replace(match):
        return chr(int(match.group(1), 16))

    decoded = UNICODE_ESCAPE_RE.sub(
        unicode_replace,
        decoded,
    )

    return decoded


# ============================================================
# URL handling
# ============================================================

DANGEROUS_SCHEME_RE = re.compile(
    r"(?i)(?:javascript|data|vbscript)\s*:"
)


def has_explicit_dangerous_scheme(value: str) -> bool:
    return bool(DANGEROUS_SCHEME_RE.search(value))


def parse_url(value: str):
    value = value.strip()

    # Protocol-relative URL counts as HTTPS.
    if value.startswith("//"):
        return urlparse("https:" + value)

    return urlparse(value)


def url_scheme_is_dangerous(value: str) -> bool:
    value = value.strip()

    # Explicit dangerous schemes.
    if has_explicit_dangerous_scheme(value):
        return True

    # Protocol-relative URL is treated as https.
    if value.startswith("//"):
        return False

    parsed = urlparse(value)

    # A URL with no scheme is relative.
    if not parsed.scheme:
        return False

    # Only HTTP and HTTPS are allowed.
    return parsed.scheme.lower() not in {
        "http",
        "https",
    }


def is_absolute_url(value: str) -> bool:
    value = value.strip()

    # Assignment explicitly says //host/path is absolute.
    if value.startswith("//"):
        return True

    parsed = urlparse(value)

    return bool(parsed.scheme)


def has_external_host(value: str) -> bool:
    value = value.strip()

    # Relative URLs are allowed.
    if not is_absolute_url(value):
        return False

    parsed = parse_url(value)

    # If an absolute URL has no hostname, reject it.
    hostname = parsed.hostname

    if hostname is None:
        return True

    hostname = hostname.lower()

    # EXACT hostname match.
    return hostname not in ALLOWED_HOSTS


# ============================================================
# URL extraction
# ============================================================

HTML_URL_RE = re.compile(
    r"""(?is)\b(?:src|href)\s*=\s*(["'])(.*?)\1"""
)


MARKDOWN_URL_RE = re.compile(
    r"""\]\(\s*(?:<([^>]+)>|([^\s)]+))\s*\)""",
    re.IGNORECASE,
)


def extract_html_urls(value: str) -> list[str]:
    urls = []

    for match in HTML_URL_RE.finditer(value):
        urls.append(match.group(2))

    return urls


def extract_markdown_urls(value: str) -> list[str]:
    urls = []

    for match in MARKDOWN_URL_RE.finditer(value):
        if match.group(1) is not None:
            urls.append(match.group(1))
        elif match.group(2) is not None:
            urls.append(match.group(2))

    return urls


# ============================================================
# HTML rules
# ============================================================

def html_has_script_tag(value: str) -> bool:
    pattern = re.compile(
        r"(?is)<\s*(?:script|iframe|object|embed)\b"
    )

    return bool(pattern.search(value))


def html_has_event_handler(value: str) -> bool:
    # Detect an attribute beginning with "on", followed by
    # one or more attribute-name characters, then "=".
    #
    # Examples:
    # onclick=
    # onerror=
    # onload=

    pattern = re.compile(
        r"""(?is)(?:^|[\s<])on[a-zA-Z0-9_-]+\s*="""
    )

    return bool(pattern.search(value))


# ============================================================
# Channel checks
# ============================================================

def check_html(value: str):
    # 1. SCRIPT_TAG
    if html_has_script_tag(value):
        return "SCRIPT_TAG"

    # 2. EVENT_HANDLER
    if html_has_event_handler(value):
        return "EVENT_HANDLER"

    urls = extract_html_urls(value)

    # 3. DANGEROUS_SCHEME
    if has_explicit_dangerous_scheme(value):
        return "DANGEROUS_SCHEME"

    for url in urls:
        if url_scheme_is_dangerous(url):
            return "DANGEROUS_SCHEME"

    # 4. EXTERNAL_EXFIL
    for url in urls:
        if has_external_host(url):
            return "EXTERNAL_EXFIL"

    return None


def check_markdown(value: str):
    urls = extract_markdown_urls(value)

    # 1. DANGEROUS_SCHEME
    if has_explicit_dangerous_scheme(value):
        return "DANGEROUS_SCHEME"

    for url in urls:
        if url_scheme_is_dangerous(url):
            return "DANGEROUS_SCHEME"

    # 2. EXTERNAL_EXFIL
    for url in urls:
        if has_external_host(url):
            return "EXTERNAL_EXFIL"

    return None


def check_url(value: str):
    url = value.strip()

    # 1. DANGEROUS_SCHEME
    if url_scheme_is_dangerous(url):
        return "DANGEROUS_SCHEME"

    # 2. EXTERNAL_EXFIL
    if has_external_host(url):
        return "EXTERNAL_EXFIL"

    return None


def check_sql(value: str):
    lowered = value.lower()

    # single quote
    if "'" in value:
        return "SQL_METACHAR"

    # double quote
    if '"' in value:
        return "SQL_METACHAR"

    # semicolon
    if ";" in value:
        return "SQL_METACHAR"

    # SQL line comment
    if "--" in value:
        return "SQL_METACHAR"

    # SQL block comment
    if "/*" in value:
        return "SQL_METACHAR"

    # word "union"
    if re.search(r"\bunion\b", lowered):
        return "SQL_METACHAR"

    # or 1=1
    if re.search(r"\bor\s+1\s*=\s*1\b", lowered):
        return "SQL_METACHAR"

    return None


def check_shell(value: str):
    # ; & | ` < >
    if re.search(r"[;&|`<>]", value):
        return "SHELL_METACHAR"

    # $(
    if "$(" in value:
        return "SHELL_METACHAR"

    # ${
    if "${" in value:
        return "SHELL_METACHAR"

    return None


def check_channel(channel: str, value: str):
    if channel == "html":
        return check_html(value)

    if channel == "markdown":
        return check_markdown(value)

    if channel == "url":
        return check_url(value)

    if channel == "sql":
        return check_sql(value)

    if channel == "shell":
        return check_shell(value)

    return "INVALID_SCHEMA"


# ============================================================
# Main endpoint
# ============================================================

@app.post("/sanitize-output")
async def sanitize_output(request: Request):

    # Read raw request body first.
    raw_body = await request.body()

    # Parse JSON ourselves so malformed JSON is always handled
    # as INVALID_SCHEMA rather than exposing FastAPI's default
    # validation response.
    try:
        body = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return reject("INVALID_SCHEMA")

    # --------------------------------------------------------
    # Rule 1
    # --------------------------------------------------------

    if not valid_schema(body):
        return reject("INVALID_SCHEMA")

    channel = body["channel"]
    output = body["output"]

    # --------------------------------------------------------
    # Rule 2
    # Decode exactly once.
    # --------------------------------------------------------

    decoded = decode_once(output)

    if decoded != output:

        decoded_reason = check_channel(
            channel,
            decoded,
        )

        if decoded_reason is not None:
            return reject("ENCODED_PAYLOAD")

    # --------------------------------------------------------
    # Rule 3
    # Check ORIGINAL output.
    # --------------------------------------------------------

    reason = check_channel(
        channel,
        output,
    )

    if reason is not None:
        return reject(reason)

    return accept()


# ============================================================
# Health / availability
# ============================================================

@app.get("/health")
async def health():
    return {
        "status": "ok"
    }


@app.get("/")
async def root():
    return {
        "status": "ok"
    }


# Local development only.
if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "10000"))

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
    )
