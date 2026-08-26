#!/usr/bin/env python3

import datetime
import hashlib
import hmac
import sqlite3
from pathlib import Path

import yaml
from flask import Flask, abort, request, render_template_string


# ============================================================================
# Configuration
# ============================================================================

BASE_DIR = Path(__file__).resolve().parent

CONFIG_FILE = BASE_DIR / "config.yaml"

with CONFIG_FILE.open("r", encoding="utf-8") as f:
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
# Example:
#
#   printf '%s' 'your-long-password' | sha256sum
#
# Put the resulting 64-character hexadecimal digest in config.yaml:
#
#   password_sha256: "..."
#
PASSWORD_SHA256 = str(
    config.get("password_sha256", "")
).strip().lower()

if (
    len(PASSWORD_SHA256) != 64
    or any(c not in "0123456789abcdef" for c in PASSWORD_SHA256)
):
    raise RuntimeError(
        "config.yaml must contain a valid 64-character "
        "password_sha256 hexadecimal digest"
    )

# History display is bounded.
#
# This does NOT affect uptime calculation.
MAX_HISTORY_EVENTS = max(
    1,
    min(int(config.get("max_history_events", 1000)), 10000),
)

# Authentication failure throttling.
#
# This is deliberately simple and bounded. It is not intended to replace
# Tor access control.
AUTH_MAX_FAILURES = max(
    1,
    min(int(config.get("auth_max_failures", 10)), 1000),
)

AUTH_LOCKOUT_SECONDS = max(
    1,
    min(int(config.get("auth_lockout_seconds", 60)), 3600),
)


# ============================================================================
# Flask
# ============================================================================

app = Flask(
    __name__,
    static_folder=None,
)

# No Flask session is used.
# No cookies are required.
# HTTP Basic Authentication is used only to request the password.


# ============================================================================
# Database
# ============================================================================

def db():
    """
    Open SQLite read-only.

    Filesystem permissions must independently ensure that the account
    running this process cannot modify the database or its directory.
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
    """
    Return a Basic Auth challenge.

    Only the password is meaningful. The username is deliberately ignored.
    """

    response = (
        "Authentication required",
        401,
        {
            "WWW-Authenticate": 'Basic realm="OnionWatcher"',
            "Cache-Control": "no-store",
        },
    )

    return response


def authenticated():
    """
    Validate the HTTP Basic Authentication password.

    The username is ignored.

    The supplied password is hashed with SHA-256 and compared with the
    configured digest using constant-time comparison.
    """

    global auth_failures
    global auth_locked_until

    import base64
    import time

    now = time.monotonic()

    # Temporary lockout applies only after repeated failures.
    if now < auth_locked_until:
        return False

    header = request.headers.get("Authorization", "")

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

    # Basic Auth is username:password.
    #
    # The username is ignored. split(":", 1) is important because the
    # password itself may contain ':'.
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
        # Successful authentication clears the failure state.
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
    """
    Protect every HTTP endpoint.

    The application is intended to sit behind a Tor onion service.
    Authentication is an additional application-level password boundary.
    """

    if not authenticated():
        return unauthorized()


# ============================================================================
# Security headers
# ============================================================================

@app.after_request
def security_headers(response):

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'none'; "
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
    Accept only:

        YYYY-MM-DDTHH:MM:SS.ffffff

    The database timestamp is interpreted as UTC.
    """

    if not isinstance(value, str):
        return None

    # Reject non-canonical representations explicitly.
    if len(value) != 26:
        return None

    try:
        dt = datetime.datetime.strptime(
            value,
            DB_TIME_FORMAT,
        )
    except ValueError:
        return None

    return dt.replace(tzinfo=UTC)


def database_timestamp(dt):
    return dt.astimezone(UTC).strftime(
        DB_TIME_FORMAT
    )


# ============================================================================
# Formatting
# ============================================================================

def format_duration(seconds):

    seconds = max(0, int(seconds))

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
        parts.append(f"{days}d")

    if hours:
        parts.append(f"{hours}h")

    if minutes:
        parts.append(f"{minutes}m")

    return (
        " ".join(parts)
        if parts
        else "<1m"
    )


# ============================================================================
# Services
# ============================================================================

def services():

    conn = db()

    try:

        return conn.execute(
            """
            SELECT
                services.id,
                services.name,
                services.host,
                service_state.status
            FROM services
            JOIN service_state
              ON services.id = service_state.service_id
            ORDER BY services.name
            """
        ).fetchall()

    finally:
        conn.close()


def service(service_id):

    conn = db()

    try:

        return conn.execute(
            """
            SELECT
                services.id,
                services.name,
                services.host,
                service_state.status
            FROM services
            JOIN service_state
              ON services.id = service_state.service_id
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
    Fetch the state immediately before the window and every event in the
    requested window.

    There is deliberately no LIMIT here.
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
# History
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

    raw = uptime_events(
        service_id,
        start,
        now,
    )

    events = []

    for event in raw:

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

    # Establish state at the start of the reporting window.
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

    # Events exactly at the start take effect immediately.
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

        # Events are consumed exactly once.
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

        # Account for the remainder of the block.
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
# Templates
# ============================================================================

INDEX = """
<!doctype html>

<html lang="en">

<head>

<meta charset="utf-8">

<meta name="viewport"
      content="width=device-width,initial-scale=1">

<title>OnionWatcher</title>

<style>

body {
    font-family: monospace;
    background: #111;
    color: #eee;
    margin: 2rem;
}

table {
    border-collapse: collapse;
    width: 100%;
    max-width: 1100px;
}

td,
th {
    padding: 8px;
    text-align: left;
}

tr:nth-child(even) {
    background: #181818;
}

a {
    color: #66aaff;
}

.online {
    color: #00cc66;
}

.offline {
    color: #cc3333;
}

.unknown {
    color: #999;
}

.bar {
    display: flex;
    width: 300px;
    height: 8px;
}

.block {
    flex: 1;
}

.block.green {
    background: #00aa00;
}

.block.red {
    background: #aa0000;
}

.block.gray {
    background: #555;
}

.small {
    color: #999;
    font-size: 0.9em;
}

</style>

</head>

<body>

<h1>OnionWatcher</h1>

<p class="small">
Last {{ uptime_days }}
{{ "day" if uptime_days == 1 else "days" }}.
Uptime is calculated only over periods where the state is known.
</p>

<table>

<thead>

<tr>
<th>Service</th>
<th>History</th>
<th>Uptime</th>
<th>Coverage</th>
<th>Onion</th>
</tr>

</thead>

<tbody>

{% for s in services %}

<tr>

<td>

<a href="/service/{{ s.id }}"
   class="{{ s.status }}">

{{ s.name }}

</a>

</td>

<td>

<div class="bar"
     aria-label="Hourly uptime history">

{% for block in bars[s.id] %}

<div class="block {{ block }}"></div>

{% endfor %}

</div>

</td>

<td>

{% if uptime[s.id] is none %}

<span class="unknown">
unknown
</span>

{% else %}

{{ "%.2f"|format(uptime[s.id]) }}%

{% endif %}

</td>

<td>

{{ "%.2f"|format(coverage[s.id]) }}%

</td>

<td>

{{ s.host }}

</td>

</tr>

{% endfor %}

</tbody>

</table>

</body>

</html>
"""


SERVICE = """
<!doctype html>

<html lang="en">

<head>

<meta charset="utf-8">

<meta name="viewport"
      content="width=device-width,initial-scale=1">

<title>{{ service.name }} - OnionWatcher</title>

<style>

body {
    font-family: monospace;
    background: #111;
    color: #eee;
    margin: 2rem;
}

a {
    color: #66aaff;
}

.online {
    color: #00ff66;
}

.offline {
    color: #cc3333;
}

.unknown {
    color: #999;
}

.event {
    margin: 0.25rem 0;
}

</style>

</head>

<body>

<p>
<a href="/">Back</a>
</p>

<h1>{{ service.name }}</h1>

<p>
Current status:
<span class="{{ service.status }}">
{{ service.status }}
</span>
</p>

<p>
{{ service.host }}
</p>

{% if events %}

{% for event in events %}

<div class="event {{ event.status }}">

{{ event.timestamp }}

({{ event.duration }})

</div>

{% endfor %}

{% else %}

<p class="unknown">
No valid history available.
</p>

{% endif %}

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
    coverage = {}
    bars = {}

    for s in svcs:

        u, c, b = uptime_data(
            s["id"]
        )

        uptime[s["id"]] = u
        coverage[s["id"]] = c
        bars[s["id"]] = b

    return render_template_string(
        INDEX,
        services=svcs,
        uptime=uptime,
        coverage=coverage,
        bars=bars,
        uptime_days=UPTIME_DAYS,
    )


@app.route("/service/<int:service_id>")
def service_page(service_id):

    svc = service(service_id)

    if svc is None:
        abort(404)

    raw_events = history_events(
        service_id
    )

    now = datetime.datetime.now(UTC)

    parsed = []

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

        parsed.append(
            (
                timestamp,
                status,
            )
        )

    history = []

    for index, (
        timestamp,
        status,
    ) in enumerate(parsed):

        if index == 0:
            end = now
        else:
            end = parsed[
                index - 1
            ][0]

        duration = max(
            0,
            (
                end - timestamp
            ).total_seconds(),
        )

        history.append(
            {
                "timestamp":
                    timestamp.strftime(
                        "%Y-%m-%d %H:%M:%S UTC"
                    ),

                "status": status,

                "duration":
                    format_duration(
                        duration
                    ),
            }
        )

    return render_template_string(
        SERVICE,
        service=svc,
        events=history,
    )


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
# Localhost-only development entry point
# ============================================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=PORT,
        debug=False,
    )
