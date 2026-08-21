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


def respond(safe: bool, reason: str):
    return JSONResponse(
        status_code=200,
        content={
            "safe": safe,
            "reason": reason,
        },
    )


# ============================================================
# Schema
# ============================================================

def valid_schema(body: Any) -> bool:
    return (
        isinstance(body, dict)
        and body.get("channel") in VALID_CHANNELS
        and isinstance(body.get("output"), str)
        and len(body["output"]) <= 20000
    )


# ============================================================
# Decode once
# ============================================================

HTML_ENTITIES = {
    "&lt;": "<",
    "&gt;": ">",
    "&quot;": '"',
    "&apos;": "'",
    "&amp;": "&",
}

NUMERIC_ENTITY = re.compile(
    r"&#([0-9]+);|&#x([0-9a-fA-F]+);",
    re.IGNORECASE,
)

UNICODE_ESCAPE = re.compile(
    r"\\u([0-9a-fA-F]{4})"
)


def decode_once(value: str) -> str:
    # Percent escapes
    value = unquote(value)

    # Exact named entities required by assignment
    for entity, replacement in HTML_ENTITIES.items():
        value = value.replace(entity, replacement)

    # Numeric HTML entities
    def numeric(m):
        try:
            number = (
                int(m.group(1), 10)
                if m.group(1) is not None
                else int(m.group(2), 16)
            )
            return chr(number)
        except (ValueError, OverflowError):
            return m.group(0)

    value = NUMERIC_ENTITY.sub(numeric, value)

    # \uXXXX
    def unicode(m):
        return chr(int(m.group(1), 16))

    value = UNICODE_ESCAPE.sub(unicode, value)

    return value


# ============================================================
# URL checks
# ============================================================

DANGEROUS_SCHEME = re.compile(
    r"(?i)(?:javascript|data|vbscript)\s*:"
)


def parse_url(value: str):
    value = value.strip()

    if value.startswith("//"):
        return urlparse("https:" + value)

    return urlparse(value)


def dangerous_scheme(value: str) -> bool:
    value = value.strip()

    if DANGEROUS_SCHEME.search(value):
        return True

    if value.startswith("//"):
        return False

    parsed = urlparse(value)

    if not parsed.scheme:
        return False

    return parsed.scheme.lower() not in {"http", "https"}


def absolute_url(value: str) -> bool:
    value = value.strip()

    if value.startswith("//"):
        return True

    return bool(urlparse(value).scheme)


def external_url(value: str) -> bool:
    value = value.strip()

    if not absolute_url(value):
        return False

    parsed = parse_url(value)

    if parsed.hostname is None:
        return True

    return parsed.hostname.lower() not in ALLOWED_HOSTS


# ============================================================
# URL extraction
# ============================================================

HTML_URL = re.compile(
    r"""(?is)\b(?:src|href)\s*=\s*(["'])(.*?)\1"""
)

MARKDOWN_URL = re.compile(
    r"""\]\(\s*(?:<([^>]+)>|([^\s)]+))\s*\)"""
)


def html_urls(value: str):
    return [m.group(2) for m in HTML_URL.finditer(value)]


def markdown_urls(value: str):
    result = []

    for m in MARKDOWN_URL.finditer(value):
        result.append(
            m.group(1)
            if m.group(1) is not None
            else m.group(2)
        )

    return result


# ============================================================
# Channel checks
# ============================================================

def check_html(value: str):
    # SCRIPT_TAG
    if re.search(
        r"(?is)<\s*(?:script|iframe|object|embed)\b",
        value,
    ):
        return "SCRIPT_TAG"

    # EVENT_HANDLER
    if re.search(
        r"""(?is)(?:^|[\s<])on[a-zA-Z0-9_-]+\s*=""",
        value,
    ):
        return "EVENT_HANDLER"

    urls = html_urls(value)

    # DANGEROUS_SCHEME
    if DANGEROUS_SCHEME.search(value):
        return "DANGEROUS_SCHEME"

    for url in urls:
        if dangerous_scheme(url):
            return "DANGEROUS_SCHEME"

    # EXTERNAL_EXFIL
    for url in urls:
        if external_url(url):
            return "EXTERNAL_EXFIL"

    return None


def check_markdown(value: str):
    urls = markdown_urls(value)

    # DANGEROUS_SCHEME
    if DANGEROUS_SCHEME.search(value):
        return "DANGEROUS_SCHEME"

    for url in urls:
        if dangerous_scheme(url):
            return "DANGEROUS_SCHEME"

    # EXTERNAL_EXFIL
    for url in urls:
        if external_url(url):
            return "EXTERNAL_EXFIL"

    return None


def check_url(value: str):
    value = value.strip()

    if dangerous_scheme(value):
        return "DANGEROUS_SCHEME"

    if external_url(value):
        return "EXTERNAL_EXFIL"

    return None


def check_sql(value: str):
    lower = value.lower()

    if "'" in value:
        return "SQL_METACHAR"

    if '"' in value:
        return "SQL_METACHAR"

    if ";" in value:
        return "SQL_METACHAR"

    if "--" in value:
        return "SQL_METACHAR"

    if "/*" in value:
        return "SQL_METACHAR"

    if re.search(r"\bunion\b", lower):
        return "SQL_METACHAR"

    if re.search(r"\bor\s+1\s*=\s*1\b", lower):
        return "SQL_METACHAR"

    return None


def check_shell(value: str):
    if re.search(r"[;&|`<>]", value):
        return "SHELL_METACHAR"

    if "$(" in value:
        return "SHELL_METACHAR"

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
# POST /sanitize-output
# ============================================================

@app.post("/sanitize-output")
async def sanitize_output(request: Request):

    raw = await request.body()

    try:
        body = json.loads(raw.decode("utf-8"))
    except Exception:
        return respond(False, "INVALID_SCHEMA")

    if not valid_schema(body):
        return respond(False, "INVALID_SCHEMA")

    channel = body["channel"]
    output = body["output"]

    decoded = decode_once(output)

    if decoded != output:
        if check_channel(channel, decoded) is not None:
            return respond(False, "ENCODED_PAYLOAD")

    reason = check_channel(channel, output)

    if reason is not None:
        return respond(False, reason)

    return respond(True, "SAFE")


# ============================================================
# Health / deployment diagnostic endpoints
# ============================================================

@app.get("/health")
async def health():
    return JSONResponse(
        status_code=200,
        content={"status": "ok"},
    )


@app.get("/")
async def root():
    return JSONResponse(
        status_code=200,
        content={"status": "ok"},
    )


@app.get("/version")
async def version():
    return JSONResponse(
        status_code=200,
        content={
            "service": "llm-output-gate",
            "version": "2",
        },
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "10000")),
    )
