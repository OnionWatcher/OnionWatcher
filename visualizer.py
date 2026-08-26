#!/usr/bin/env python3

import sqlite3
import yaml
import datetime
import hashlib
import hmac
import base64
import time

from flask import Flask, render_template_string, request, abort


# ============================================================================
# Configuration
# ============================================================================

with open("config.yaml", encoding="utf-8") as f:
    config = yaml.safe_load(f) or {}

DB = config.get("database", "onionwatcher.db")
PORT = int(config.get("web_port", 8080))
UPTIME_DAYS = int(config.get("uptime_days", 7))

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


# ============================================================================
# Authentication throttling
# ============================================================================

AUTH_MAX_FAILURES = max(
    1,
    min(int(config.get("auth_max_failures", 10)), 1000),
)

AUTH_LOCKOUT_SECONDS = max(
    1,
    min(int(config.get("auth_lockout_seconds", 60)), 3600),
)

auth_failures = 0
auth_locked_until = 0.0


# ============================================================================
# Flask
# ============================================================================

app = Flask(__name__)


# ============================================================================
# Authentication
# ============================================================================

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
    global auth_failures
    global auth_locked_until

    now = time.monotonic()

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

    # HTTP Basic Authentication is username:password.
    # The username is deliberately ignored.
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
        auth_failures = 0
        auth_locked_until = (
            now + AUTH_LOCKOUT_SECONDS
        )

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
# Database
# ============================================================================

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================================
# Formatting
# ============================================================================

def format_duration(seconds):

    seconds = int(seconds)

    days = seconds // 86400
    seconds %= 86400

    hours = seconds // 3600
    seconds %= 3600

    minutes = seconds // 60

    parts = []

    if days:
        parts.append(f"{days}d")

    if hours:
        parts.append(f"{hours}h")

    if minutes:
        parts.append(f"{minutes}m")

    if not parts:
        return "<1m"

    return " ".join(parts)


# ============================================================================
# Services
# ============================================================================

def services():

    c = db()

    try:

        rows = c.execute("""
            SELECT
                services.*,
                service_state.status
            FROM services
            JOIN service_state
            ON services.id = service_state.service_id
            WHERE services.id IN (
                SELECT service_id
                FROM service_state
            )
            ORDER BY services.name
        """).fetchall()

        return rows

    finally:
        c.close()


def service(service_id):

    c = db()

    try:

        return c.execute("""
            SELECT
                services.*,
                service_state.status
            FROM services
            JOIN service_state
            ON services.id = service_state.service_id
            WHERE services.id = ?
        """, (service_id,)).fetchone()

    finally:
        c.close()


def events(service_id):

    c = db()

    try:

        rows = c.execute("""
            SELECT *
            FROM events
            WHERE service_id=?
            ORDER BY timestamp ASC
        """, (service_id,)).fetchall()

        return rows

    finally:
        c.close()


# ============================================================================
# Uptime
# ============================================================================

def uptime_data(service_id):

    now = datetime.datetime.utcnow()
    start = now - datetime.timedelta(days=UPTIME_DAYS)

    ev = events(service_id)

    if not ev:
        return 0, ["red"] * (UPTIME_DAYS * 24)

    offline = False
    offline_start = start
    offline_seconds = 0

    for e in ev:

        # IMPORTANT:
        # Keep the original fromisoformat() behavior.
        # Do not require a specific microsecond format.
        t = datetime.datetime.fromisoformat(
            e["timestamp"]
        )

        if t < start:
            continue

        if e["new_status"] == "offline":

            offline = True
            offline_start = max(
                t,
                start,
            )

        elif (
            e["new_status"] == "online"
            and offline
        ):

            offline = False

            offline_seconds += (
                min(t, now) - offline_start
            ).total_seconds()

    if offline:

        offline_seconds += (
            now - offline_start
        ).total_seconds()

    total = (
        now - start
    ).total_seconds()

    uptime = max(
        0,
        100 * (
            total - offline_seconds
        ) / total
    )

    blocks = []

    hours = UPTIME_DAYS * 24

    for i in range(hours):

        a = (
            start
            + datetime.timedelta(
                hours=i
            )
        )

        b = (
            a
            + datetime.timedelta(
                hours=1
            )
        )

        offline_time = 0

        # Preserve original behavior:
        # assume online until an event says otherwise.
        state = "online"

        # Determine state at beginning of block.
        for e in ev:

            t = datetime.datetime.fromisoformat(
                e["timestamp"]
            )

            if t <= a:
                state = e["new_status"]
            else:
                break

        cursor = a

        for e in ev:

            t = datetime.datetime.fromisoformat(
                e["timestamp"]
            )

            if t <= a:
                continue

            if t >= b:
                break

            if state == "offline":

                offline_time += (
                    t - cursor
                ).total_seconds()

            state = e["new_status"]
            cursor = t

        if state == "offline":

            offline_time += (
                b - cursor
            ).total_seconds()

        blocks.append(
            "red"
            if offline_time > 0
            else "green"
        )

    return uptime, blocks


# ============================================================================
# Dashboard
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

td,th {
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
    .catch(function(error) {

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

<!--
     This is a real /service/<id> link.
     JavaScript intercepts the click and loads the same endpoint
     into the details div.
-->
<a
    href="/service/{{s.id}}"
    onclick="showDetails({{s.id}}); return false;"
    class="{{s.status}}"
>
{{s.name}}
</a>

</td>

<td>

<div class="bar">

{% for c in bars[s.id] %}

<div class="block {{c}}"></div>

{% endfor %}

</div>

</td>

<td>

{{"%.2f"|format(
    uptime[s.id]
)}}%

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
# Index
# ============================================================================

@app.route("/")
def index():

    svcs = services()

    uptime = {}
    bars = {}

    for s in svcs:

        u, b = uptime_data(
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
# Service history
# ============================================================================

@app.route("/service/<int:id>")
def service_page(id):

    svc = service(id)

    if svc is None:
        abort(404)

    ev = events(id)

    rev = list(
        reversed(ev)
    )

    result = ""

    now = datetime.datetime.utcnow()

    for i, e in enumerate(rev):

        # IMPORTANT:
        # Use the same parser as the original working script.
        t = datetime.datetime.fromisoformat(
            e["timestamp"]
        )

        if i == 0:

            duration = (
                now - t
            ).total_seconds()

        else:

            next_event = rev[i - 1]

            next_time = datetime.datetime.fromisoformat(
                next_event["timestamp"]
            )

            duration = (
                next_time - t
            ).total_seconds()

        color = (
            "#00ff66"
            if e["new_status"] == "online"
            else "#cc3333"
        )

        result += (
            f'<div style="color:{color};">'
            f'{e["timestamp"]} '
            f'({format_duration(duration)})'
            f'</div>'
        )

    if not result:

        return (
            '<div style="color:#999;">'
            'No history available.'
            '</div>'
        )

    return result


# ============================================================================
# Status endpoint
# ============================================================================

@app.route(
    "/status/<string:service_name>"
)
def status(service_name):

    c = db()

    try:

        row = c.execute("""
            SELECT service_state.status
            FROM services
            JOIN service_state
            ON services.id = service_state.service_id
            WHERE services.name = ?
        """, (service_name,)).fetchone()

    finally:

        c.close()

    if row is None:
        return "0", 404

    return (
        "1"
        if row["status"] == "online"
        else "0"
    )


# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=PORT,
        debug=False,
    )
