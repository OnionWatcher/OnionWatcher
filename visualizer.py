#!/usr/bin/env python3

import base64
import datetime
import hashlib
import hmac
import sqlite3
import time
from pathlib import Path

import yaml
from flask import Flask, abort, request, render_template_string


# ============================================================================
# Configuration
# ============================================================================

BASE_DIR = Path(__file__).resolve().parent

with open(BASE_DIR / "config.yaml", "r", encoding="utf-8") as f:
    config = yaml.safe_load(f) or {}

DB = Path(config.get("database", "onionwatcher.db"))

if not DB.is_absolute():
    DB = BASE_DIR / DB

PORT = int(config.get("web_port", 8080))

UPTIME_DAYS = max(
    1,
    min(int(config.get("uptime_days", 7)), 365),
)

# Password SHA-256 digest.
#
# Generate with:
#
#   printf '%s' 'your-password' | sha256sum
#
# Then put the 64-character digest in config.yaml:
#
#   password_sha256: "..."
#
PASSWORD_SHA256 = str(
    config.get("password_sha256", "")
).strip().lower()

if (
    len(PASSWORD_SHA256) != 64
    or any(
        c not in "0123456789abcdef"
        for c in PASSWORD_SHA256
    )
):
    raise RuntimeError(
        "config.yaml must contain a valid 64-character "
        "password_sha256 hexadecimal digest"
    )

# Maximum number of history events displayed when clicking a service.
#
# This does NOT affect uptime calculation.
MAX_HISTORY_EVENTS = max(
    1,
    min(
        int(config.get("max_history_events", 1000)),
        10000,
    ),
)

# Simple bounded authentication lockout.
AUTH_MAX_FAILURES = max(
    1,
    min(
        int(config.get("auth_max_failures", 10)),
        1000,
    ),
)

AUTH_LOCKOUT_SECONDS = max(
    1,
    min(
        int(config.get("auth_lockout_seconds", 60)),
        3600,
    ),
)


# ============================================================================
# Flask
# ============================================================================

app = Flask(
    __name__,
    static_folder=None,
)


# ============================================================================
# Database
# ============================================================================

def db():
    """
    Open SQLite read-only.

    Filesystem permissions should independently prevent this process
    from modifying the database.
    """

    uri = DB.resolve().as_uri() + "?mode=ro"

    conn = sqlite3.connect(
        uri,
        uri=True,
        timeout=5,
    )

    conn.row_factory = sqlite3.Row

    # Defense in depth.
    conn.execute("PRAGMA query_only = ON")

    return conn


# ============================================================================
# Authentication
# ============================================================================

auth_failures = 0
auth_locked_until = 0.0


def unauthorized():
    return (
        "Authentication required",
        401,
        {
            "WWW-Authenticate": 'Basic realm="OnionWatcher"',
            "Cache-Control": "no-store",
        },
    )


def authenticated():
    """
    HTTP Basic Authentication.

    Only the password matters.
    The username is ignored.

    The password is SHA-256 hashed and compared against the configured
    digest using constant-time comparison.
    """

    global auth_failures
    global auth_locked_until

    now = time.monotonic()

    if now < auth_locked_until:
        return False

    header = request.headers.get(
        "Authorization",
        "",
    )

    if not header.startswith("Basic "):
        return False

    encoded = header[6:].strip()

    try:
        decoded = base64.b64decode(
            encoded,
            validate=True,
        ).decode("utf-8")

    except (
        ValueError,
        UnicodeDecodeError,
    ):
        return False

    # Basic Auth is:
    #
    #     username:password
    #
    # Ignore the username.
    #
    # split(":", 1) is important because passwords may contain ':'.

    if ":" not in decoded:
        return False

    _, password = decoded.split(":", 1)

    supplied_digest = hashlib.sha256(
        password.encode("utf-8")
    ).hexdigest()

    if hmac.compare_digest(
        supplied_digest,
        PASSWORD_SHA256,
    ):
        auth_failures = 0
        auth_locked_until = 0.0

        return True

    auth_failures += 1

    if auth_failures >= AUTH_MAX_FAILURES:

        auth_locked_until = (
            now + AUTH_LOCKOUT_SECONDS
        )

        auth_failures = 0

    return False


@app.before_request
def require_authentication():

    if not authenticated():
        return unauthorized()


# ============================================================================
# Security headers
# ============================================================================

@app.after_request
def security_headers(response):

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'unsafe-inline'; "
        "style-src 'unsafe-inline'; "
        "img-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'none'; "
        "frame-ancestors 'none'"
    )

    response.headers["X-Content-Type-Options"] = "nosniff"

    response.headers["X-Frame-Options"] = "DENY"

    response.headers["Referrer-Policy"] = "no-referrer"

    response.headers["Cache-Control"] = "no-store"

    return response


# ============================================================================
# Time handling
# ============================================================================

UTC = datetime.timezone.utc

DB_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"


def parse_timestamp(value):
    """
    Parse the timestamp format used by the existing database.

    Example:

        2026-08-26T12:34:56.123456
    """

    if not isinstance(value, str):
        return None

    try:
        dt = datetime.datetime.strptime(
            value,
            DB_TIME_FORMAT,
        )

    except ValueError:
        return None

    return dt.replace(
        tzinfo=UTC
    )


def database_timestamp(dt):
    return dt.astimezone(
        UTC
    ).strftime(
        DB_TIME_FORMAT
    )


# ============================================================================
# Formatting
# ============================================================================

def format_duration(seconds):

    seconds = max(
        0,
        int(seconds),
    )

    days, seconds = divmod(
        seconds,
        86400,
    )

    hours, seconds = divmod(
        seconds,
        3600,
    )

    minutes, _ = divmod(
        seconds,
        60,
    )

    parts = []

    if days:
        parts.append(
            f"{days}d"
        )

    if hours:
        parts.append(
            f"{hours}h"
        )

    if minutes:
        parts.append(
            f"{minutes}m"
        )

    if not parts:
        return "<1m"

    return " ".join(parts)


# ============================================================================
# Services
# ============================================================================

def services():

    conn = db()

    try:

        rows = conn.execute(
            """
            SELECT
                services.*,
                service_state.status
            FROM services
            JOIN service_state
              ON services.id =
                 service_state.service_id
            WHERE services.id IN (
                SELECT service_id
                FROM service_state
            )
            ORDER BY services.name
            """
        ).fetchall()

        return rows

    finally:
        conn.close()


def service(service_id):

    conn = db()

    try:

        return conn.execute(
            """
            SELECT
                services.*,
                service_state.status
            FROM services
            JOIN service_state
              ON services.id =
                 service_state.service_id
            WHERE services.id = ?
            """,
            (service_id,),
        ).fetchone()

    finally:
        conn.close()


# ============================================================================
# Uptime events
# ============================================================================

def uptime_events(
    service_id,
    start,
    end,
):
    """
    Get:

      1. The latest event before the uptime window.
      2. Every event inside the uptime window.

    There is intentionally no LIMIT here.

    Uptime calculation therefore sees every state transition it needs.
    """

    start_s = database_timestamp(start)
    end_s = database_timestamp(end)

    conn = db()

    try:

        previous = conn.execute(
            """
            SELECT timestamp, new_status
            FROM events
            WHERE service_id = ?
              AND timestamp < ?
            ORDER BY timestamp DESC, rowid DESC
            LIMIT 1
            """,
            (
                service_id,
                start_s,
            ),
        ).fetchone()

        current = conn.execute(
            """
            SELECT timestamp, new_status
            FROM events
            WHERE service_id = ?
              AND timestamp >= ?
              AND timestamp <= ?
            ORDER BY timestamp ASC, rowid ASC
            """,
            (
                service_id,
                start_s,
                end_s,
            ),
        ).fetchall()

        result = []

        if previous is not None:
            result.append(previous)

        result.extend(current)

        return result

    finally:
        conn.close()


# ============================================================================
# History events
# ============================================================================

def history_events(service_id):

    conn = db()

    try:

        return conn.execute(
            """
            SELECT timestamp, new_status
            FROM events
            WHERE service_id = ?
            ORDER BY timestamp DESC, rowid DESC
            LIMIT ?
            """,
            (
                service_id,
                MAX_HISTORY_EVENTS,
            ),
        ).fetchall()

    finally:
        conn.close()


# ============================================================================
# Uptime calculation
# ============================================================================

def uptime_data(service_id):

    now = datetime.datetime.now(UTC)

    start = (
        now
        - datetime.timedelta(
            days=UPTIME_DAYS
        )
    )

    raw_events = uptime_events(
        service_id,
        start,
        now,
    )

    events = []

    for event in raw_events:

        timestamp = parse_timestamp(
            event["timestamp"]
        )

        if timestamp is None:
            continue

        status = event["new_status"]

        if status not in (
            "online",
            "offline",
        ):
            continue

        events.append(
            (
                timestamp,
                status,
            )
        )

    hours = UPTIME_DAYS * 24

    if not events:

        return (
            None,
            0.0,
            ["gray"] * hours,
        )

    # Establish state at the beginning of the reporting window.

    state = None
    event_index = 0

    while event_index < len(events):

        timestamp, new_state = events[
            event_index
        ]

        if timestamp >= start:
            break

        state = new_state
        event_index += 1

    # Events exactly at the beginning take effect immediately.

    while event_index < len(events):

        timestamp, new_state = events[
            event_index
        ]

        if timestamp != start:
            break

        state = new_state
        event_index += 1

    total_known = 0.0
    total_online = 0.0

    blocks = []

    current = start

    for _ in range(hours):

        block_end = min(
            current
            + datetime.timedelta(
                hours=1
            ),
            now,
        )

        cursor = current

        block_known = 0.0
        block_offline = 0.0

        # Consume events exactly once.

        while event_index < len(events):

            timestamp, new_state = events[
                event_index
            ]

            if timestamp < current:

                state = new_state
                event_index += 1
                continue

            if timestamp >= block_end:
                break

            if state is not None:

                duration = (
                    timestamp - cursor
                ).total_seconds()

                if duration > 0:

                    block_known += duration
                    total_known += duration

                    if state == "online":

                        total_online += duration

                    elif state == "offline":

                        block_offline += duration

            state = new_state
            cursor = timestamp
            event_index += 1

        # Finish the block.

        if (
            cursor < block_end
            and state is not None
        ):

            duration = (
                block_end - cursor
            ).total_seconds()

            if duration > 0:

                block_known += duration
                total_known += duration

                if state == "online":

                    total_online += duration

                elif state == "offline":

                    block_offline += duration

        if block_known == 0:

            blocks.append("gray")

        elif block_offline > 0:

            blocks.append("red")

        else:

            blocks.append("green")

        current = block_end

        if current >= now:
            break

    total = (
        now - start
    ).total_seconds()

    coverage = (
        100.0
        * total_known
        / total
        if total > 0
        else 0.0
    )

    uptime = (
        100.0
        * total_online
        / total_known
        if total_known > 0
        else None
    )

    while len(blocks) < hours:
        blocks.append("gray")

    return (
        uptime,
        coverage,
        blocks,
    )


# ============================================================================
# Dashboard template
#
# This deliberately preserves the original AJAX/details behavior.
# ============================================================================

INDEX = """
<html>

<head>

<style>

body {
    font-family: monospace;
    background:#111;
    color:#eee;
}

table {
    border-collapse:collapse;
}

td,
th {
    padding:8px;
}

.bar {
    display:flex;
    width:300px;
    height:8px;
}

.block {
    flex:1;
}

tr.service-row:nth-of-type(odd),
tr.service-dark,
.details-dark {
    background:#000000;
}

.service-gray,
.details-gray {
    background:#123;
}

.unknown {
    color:#cc3333;
}

.green {
    color:#00ff66;
}

.red {
    color:#cc3333;
}

.block.green {
    background:#00aa00;
}

.block.red {
    background:#aa0000;
}

.block.gray {
    background:#555;
}

.online {
    color:#00cc66;
}

.offline {
    color:#cc3333;
}

.details {
    display:none;
    padding:10px;
    height:8em;
    overflow-y:auto;
    width:100%;
    box-sizing:border-box;
}

</style>

<script>

function showDetails(id) {

    let d = document.getElementById(
        "details-" + id
    );

    if (d.style.display === "block") {

        d.style.display = "none";

        return;
    }

    fetch(
        "/service/" + id,
        {
            credentials: "same-origin"
        }
    )
    .then(function(response) {

        if (!response.ok) {
            throw new Error(
                "HTTP " + response.status
            );
        }

        return response.text();
    })
    .then(function(text) {

        d.innerHTML = text;

        d.style.display = "block";
    })
    .catch(function() {

        d.textContent =
            "Unable to load history.";

        d.style.display = "block";
    });
}

</script>

</head>

<body>

<h1>OnionWatcher</h1>

<table>

<colgroup>
<col>
<col>
<col>
<col>
</colgroup>

<tr>

<th>
Service
</th>

<th>
Last {{ UPTIME_DAYS }}
{{ "day" if UPTIME_DAYS == 1 else "days" }}
</th>

<th>
Uptime
</th>

<th>
Onion
</th>

</tr>

{% for s in services %}

{% set rowclass =
    'dark' if loop.index0 % 2 == 0
    else 'gray'
%}

<tr class="service-row service-{{rowclass}}">

<td>

<a href="#"
   onclick="showDetails({{s.id}}); return false;"
   class="{{s.status}}">

{{s.name}}

</a>

</td>

<td>

<div class="bar">

{% for c in bars[s.id] %}

<div class="block {{c}}">
</div>

{% endfor %}

</div>

</td>

<td>

{% if uptime[s.id] is none %}

<span class="unknown">
unknown
</span>

{% else %}

{{"%.2f"|format(
    uptime[s.id]
)}}%

{% endif %}

</td>

<td>

{{s.host}}

</td>

</tr>

<tr class="details-row details-{{rowclass}}">

<td colspan="4">

<div
    class="details"
    id="details-{{s.id}}"
></div>

</td>

</tr>

{% endfor %}

</table>

</body>

</html>
"""


# ============================================================================
# Routes
# ============================================================================

@app.route("/")
def index():

    svcs = services()

    uptime = {}
    bars = {}

    for s in svcs:

        u, _, b = uptime_data(
            s["id"]
        )

        uptime[s["id"]] = u
        bars[s["id"]] = b

    return render_template_string(
        INDEX,
        services=svcs,
        uptime=uptime,
        bars=bars,
        UPTIME_DAYS=UPTIME_DAYS,
    )


# ============================================================================
# AJAX history endpoint
#
# IMPORTANT:
# This returns ONLY the HTML fragment inserted into .details.
# It intentionally does NOT return a complete HTML document.
# ============================================================================

@app.route("/service/<int:id>")
def service_page(id):

    svc = service(id)

    if svc is None:
        abort(404)

    ev = history_events(id)

    now = datetime.datetime.now(UTC)

    result = []

    # history_events() returns newest first.

    previous_time = now

    for e in ev:

        timestamp = parse_timestamp(
            e["timestamp"]
        )

        if timestamp is None:
            continue

        status = e["new_status"]

        if status not in (
            "online",
            "offline",
        ):
            continue

        duration = max(
            0,
            (
                previous_time
                - timestamp
            ).total_seconds(),
        )

        if status == "online":

            color = "#00ff66"

        else:

            color = "#cc3333"

        result.append(
            f'<div style="color:{color};">'
            f'{e["timestamp"]} '
            f'({format_duration(duration)})'
            f'</div>'
        )

        previous_time = timestamp

    if not result:

        return (
            '<div style="color:#999;">'
            'No history available.'
            '</div>'
        )

    return "".join(result)


@app.route(
    "/status/<string:service_name>"
)
def status(service_name):

    if not (
        1 <= len(service_name) <= 128
    ):
        abort(404)

    conn = db()

    try:

        row = conn.execute(
            """
            SELECT service_state.status
            FROM services
            JOIN service_state
              ON services.id =
                 service_state.service_id
            WHERE services.name = ?
            LIMIT 1
            """,
            (service_name,),
        ).fetchone()

    finally:

        conn.close()

    if row is None:
        return "0", 404

    return (
        "1"
        if row["status"] == "online"
        else "0"
    )


# ============================================================================
# Local development / direct execution
# ============================================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=PORT,
        debug=False,
    )
