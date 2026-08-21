import html
import re
from typing import Any
from urllib.parse import urlparse, unquote

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


app = FastAPI(
    title="LLM Output Handling Gate",
    description="Deterministic OWASP LLM05 output security gate",
    version="1.0.0",
)


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


# ---------------------------------------------------------
# Helper: create the required response
# ---------------------------------------------------------

def result(safe: bool, reason: str) -> dict:
    return {
        "safe": safe,
        "reason": reason,
    }


# ---------------------------------------------------------
# Rule 1: schema validation
# ---------------------------------------------------------

def validate_schema(body: Any):
    if not isinstance(body, dict):
        return False

    channel = body.get("channel")
    output = body.get("output")

    if channel not in VALID_CHANNELS:
        return False

    if not isinstance(output, str):
        return False

    if len(output) > 20000:
        return False

    return True


# ---------------------------------------------------------
# Rule 2: decode once
#
# Required order:
#   1. Percent escapes
#   2. HTML entities
#   3. \uXXXX escapes
# ---------------------------------------------------------

UNICODE_ESCAPE_RE = re.compile(
    r"\\u([0-9a-fA-F]{4})"
)


def decode_once(value: str) -> str:
    # 1. Decode percent escapes.
    decoded = unquote(value)

    # 2. Decode the requested HTML entities.
    #
    # html.unescape also handles numeric entities and the
    # named entities specified by the assignment.
    decoded = html.unescape(decoded)

    # 3. Decode \uXXXX escapes.
    def replace_unicode(match):
        codepoint = int(match.group(1), 16)
        return chr(codepoint)

    decoded = UNICODE_ESCAPE_RE.sub(
        replace_unicode,
        decoded,
    )

    return decoded


# ---------------------------------------------------------
# URL helpers
# ---------------------------------------------------------

DANGEROUS_SCHEME_RE = re.compile(
    r"(?i)(?:javascript|data|vbscript)\s*:"
)


def has_dangerous_scheme_text(value: str) -> bool:
    return bool(DANGEROUS_SCHEME_RE.search(value))


def parse_url_for_check(value: str):
    """
    Parse a URL.

    Protocol-relative URLs such as:
        //attacker.example/path

    are treated as HTTPS, as required by the assignment.
    """

    value = value.strip()

    if value.startswith("//"):
        return urlparse("https:" + value)

    return urlparse(value)


def is_absolute_url(value: str) -> bool:
    parsed = parse_url_for_check(value)

    # A protocol-relative URL counts as absolute.
    if value.strip().startswith("//"):
        return True

    return bool(parsed.scheme)


def url_has_dangerous_scheme(value: str) -> bool:
    """
    Returns True if:
    - javascript:
    - data:
    - vbscript:
    - or another non-http/https scheme
    is present.
    """

    value = value.strip()

    # Explicit dangerous schemes, allowing whitespace before ':'.
    if has_dangerous_scheme_text(value):
        return True

    # Protocol-relative URLs are treated as HTTPS.
    if value.startswith("//"):
        return False

    parsed = urlparse(value)

    if parsed.scheme:
        return parsed.scheme.lower() not in {
            "http",
            "https",
        }

    return False


def external_host_is_disallowed(value: str) -> bool:
    """
    Check an absolute URL's parsed hostname.

    Exact hostname matching is required.
    """

    value = value.strip()

    if not is_absolute_url(value):
        # Relative references are allowed.
        return False

    parsed = parse_url_for_check(value)

    hostname = parsed.hostname

    if hostname is None:
        return True

    hostname = hostname.lower()

    return hostname not in ALLOWED_HOSTS


# ---------------------------------------------------------
# URL extraction
# ---------------------------------------------------------

# HTML:
# Extract values from quoted src="..." and href="..."
HTML_URL_RE = re.compile(
    r"""(?is)\b(?:src|href)\s*=\s*(["'])(.*?)\1"""
)


# Markdown:
# Extract target inside ](...)
MARKDOWN_URL_RE = re.compile(
    r"""\]\(\s*(?:<([^>]+)>|([^\s)]+))\s*\)""",
    re.IGNORECASE,
)


def extract_html_urls(value: str) -> list[str]:
    return [
        match.group(2)
        for match in HTML_URL_RE.finditer(value)
    ]


def extract_markdown_urls(value: str) -> list[str]:
    urls = []

    for match in MARKDOWN_URL_RE.finditer(value):
        if match.group(1) is not None:
            urls.append(match.group(1))
        else:
            urls.append(match.group(2))

    return urls


# ---------------------------------------------------------
# Rule checks
# ---------------------------------------------------------

def check_script_tag(value: str) -> bool:
    """
    Detect opening:
      <script
      <iframe
      <object
      <embed

    Case-insensitive.
    """

    pattern = re.compile(
        r"(?is)<\s*(?:script|iframe|object|embed)\b"
    )

    return bool(pattern.search(value))


def check_event_handler(value: str) -> bool:
    """
    Detect HTML event-handler attributes such as:

        onclick=
        onerror=
        onload=

    The check looks for an attribute beginning with 'on'
    followed by an attribute boundary and '='.
    """

    pattern = re.compile(
        r"""(?is)(?:^|[\s<])on[a-zA-Z0-9_-]*\s*="""
    )

    return bool(pattern.search(value))


# ---------------------------------------------------------
# HTML channel
# ---------------------------------------------------------

def check_html(value: str):
    # 1. SCRIPT_TAG
    if check_script_tag(value):
        return "SCRIPT_TAG"

    # 2. EVENT_HANDLER
    if check_event_handler(value):
        return "EVENT_HANDLER"

    # Extract URLs for the remaining checks.
    urls = extract_html_urls(value)

    # DANGEROUS_SCHEME
    if has_dangerous_scheme_text(value):
        return "DANGEROUS_SCHEME"

    for url in urls:
        if url_has_dangerous_scheme(url):
            return "DANGEROUS_SCHEME"

    # EXTERNAL_EXFIL
    for url in urls:
        if external_host_is_disallowed(url):
            return "EXTERNAL_EXFIL"

    return None


# ---------------------------------------------------------
# Markdown channel
# ---------------------------------------------------------

def check_markdown(value: str):
    urls = extract_markdown_urls(value)

    # DANGEROUS_SCHEME
    if has_dangerous_scheme_text(value):
        return "DANGEROUS_SCHEME"

    for url in urls:
        if url_has_dangerous_scheme(url):
            return "DANGEROUS_SCHEME"

    # EXTERNAL_EXFIL
    for url in urls:
        if external_host_is_disallowed(url):
            return "EXTERNAL_EXFIL"

    return None


# ---------------------------------------------------------
# URL channel
# ---------------------------------------------------------

def check_url(value: str):
    # The entire trimmed output is the URL.
    url = value.strip()

    # DANGEROUS_SCHEME
    if url_has_dangerous_scheme(url):
        return "DANGEROUS_SCHEME"

    # EXTERNAL_EXFIL
    if external_host_is_disallowed(url):
        return "EXTERNAL_EXFIL"

    return None


# ---------------------------------------------------------
# SQL channel
# ---------------------------------------------------------

def check_sql(value: str):
    lowered = value.lower()

    # Single quote
    if "'" in value:
        return "SQL_METACHAR"

    # Double quote
    if '"' in value:
        return "SQL_METACHAR"

    # Semicolon
    if ";" in value:
        return "SQL_METACHAR"

    # SQL comment
    if "--" in value:
        return "SQL_METACHAR"

    # SQL block comment
    if "/*" in value:
        return "SQL_METACHAR"

    # Word "union"
    if re.search(r"\bunion\b", lowered):
        return "SQL_METACHAR"

    # or 1=1
    if re.search(r"\bor\s+1\s*=\s*1\b", lowered):
        return "SQL_METACHAR"

    return None


# ---------------------------------------------------------
# Shell channel
# ---------------------------------------------------------

def check_shell(value: str):
    # Any of:
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


# ---------------------------------------------------------
# Apply channel-specific rules
# ---------------------------------------------------------

def check_channel(channel: str, output: str):
    if channel == "html":
        return check_html(output)

    if channel == "markdown":
        return check_markdown(output)

    if channel == "url":
        return check_url(output)

    if channel == "sql":
        return check_sql(output)

    if channel == "shell":
        return check_shell(output)

    return "INVALID_SCHEMA"


# ---------------------------------------------------------
# Main endpoint
# ---------------------------------------------------------

@app.post("/sanitize-output")
async def sanitize_output(request: Request):
    # Read JSON body.
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            result(False, "INVALID_SCHEMA")
        )

    # -----------------------------------------------------
    # Rule 1: INVALID_SCHEMA
    # -----------------------------------------------------

    if not validate_schema(body):
        return JSONResponse(
            result(False, "INVALID_SCHEMA")
        )

    channel = body["channel"]
    output = body["output"]

    # -----------------------------------------------------
    # Rule 2: ENCODED_PAYLOAD
    # -----------------------------------------------------

    decoded = decode_once(output)

    if decoded != output:
        decoded_reason = check_channel(
            channel,
            decoded,
        )

        if decoded_reason is not None:
            return JSONResponse(
                result(False, "ENCODED_PAYLOAD")
            )

    # -----------------------------------------------------
    # Rule 3: original output
    # -----------------------------------------------------

    reason = check_channel(
        channel,
        output,
    )

    if reason is not None:
        return JSONResponse(
            result(False, reason)
        )

    # -----------------------------------------------------
    # Everything passed
    # -----------------------------------------------------

    return JSONResponse(
        result(True, "SAFE")
    )


# ---------------------------------------------------------
# Health check
# ---------------------------------------------------------

@app.get("/")
def root():
    return {
        "service": "LLM Output Handling Gate",
        "status": "running",
        "endpoint": "POST /sanitize-output",
    }
