import sqlite3
import yaml
import datetime

from flask import Flask, render_template_string, jsonify


with open("config.yaml") as f:
    config = yaml.safe_load(f)

DB = config.get("database", "onionwatcher.db")
PORT = config.get("web_port", 8080)
UPTIME_DAYS = config.get("uptime_days", 7)

app = Flask(__name__)


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

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


def services():
    c = db()

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

    c.close()
    return rows


def events(service_id):
    c = db()
    rows = c.execute("""
        SELECT *
        FROM events
        WHERE service_id=?
        ORDER BY timestamp ASC
    """, (service_id,)).fetchall()
    c.close()
    return rows


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
        t = datetime.datetime.fromisoformat(e["timestamp"])

        if t < start:
            continue

        if e["new_status"] == "offline":
            offline = True
            offline_start = max(t, start)

        elif e["new_status"] == "online" and offline:
            offline = False
            offline_seconds += (
                min(t, now) - offline_start
            ).total_seconds()

    if offline:
        offline_seconds += (
            now - offline_start
        ).total_seconds()

    total = (now - start).total_seconds()

    uptime = max(
        0,
        100 * (total - offline_seconds) / total
    )

    blocks = []
    hours = UPTIME_DAYS * 24

    for i in range(hours):

        a = start + datetime.timedelta(hours=i)
        b = a + datetime.timedelta(hours=1)

        offline_time = 0

        state = "online"

        # determine state at beginning of this block
        for e in ev:
            t = datetime.datetime.fromisoformat(e["timestamp"])

            if t <= a:
                state = e["new_status"]
            else:
                break


        cursor = a

        for e in ev:

            t = datetime.datetime.fromisoformat(e["timestamp"])

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


        # mark hour red if any significant outage occurred
        blocks.append(
            "red" if offline_time > 0 else "green"
        )
    return uptime, blocks


INDEX = """
<html>
<head>
<style>
body { font-family: monospace; background:#111; color:#eee; }
table { border-collapse:collapse; }
td,th { padding:8px; }
.bar { display:flex; width:300px; height:8px; }
.block { flex:1; }

tr.service-row:nth-of-type(odd),
tr.service-dark,
.details-dark {
    background:#000000;
}

.service-gray,
.details-gray {
    background:#123;
}

.unknown { color:#cc3333; }
.green { color:#00ff66; }
.red { color:#cc3333; }

.block.green {
    background:#00aa00;
}

.block.red {
    background:#aa0000;
}
.online { color:#00cc66; }
.offline { color:#cc3333; }
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
    let d=document.getElementById("details-"+id);
    if (d.style.display==="block") {
        d.style.display="none";
        return;
    }
    fetch("/service/"+id)
    .then(r=>r.text())
    .then(t=>{
        d.innerHTML=t;
        d.style.display="block";
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
<th>Service</th>
<th>Last period</th>
<th>Uptime</th>
<th>Onion</th>
</tr>

{% for s in services %}
{% set rowclass = 'dark' if loop.index0 % 2 == 0 else 'gray' %}

<tr class="service-row service-{{rowclass}}">
<td>
<a onclick="showDetails({{s.id}})"
class="{{s.status}}">
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

<td>{{"%.2f"|format(uptime[s.id])}}%</td>

<td>{{s.host}}</td>

</tr>

<tr class="details-row details-{{rowclass}}">
<td>
<div class="details" id="details-{{s.id}}"></div>
</td>
<td colspan="3"></td>
</tr>

{% endfor %}

</table>

</body>
</html>
"""


@app.route("/")
def index():
    svcs = services()
    uptime = {}
    bars = {}

    for s in svcs:
        u, b = uptime_data(s["id"])
        uptime[s["id"]] = u
        bars[s["id"]] = b

    return render_template_string(
        INDEX,
        services=svcs,
        uptime=uptime,
        bars=bars
    )


@app.route("/service/<int:id>")
def service_page(id):

    ev = events(id)

    rev = list(reversed(ev))

    result = ""

    now = datetime.datetime.utcnow()

    for i, e in enumerate(rev):

        t = datetime.datetime.fromisoformat(
            e["timestamp"]
        )

        if i == 0:

            duration = (
                now - t
            ).total_seconds()

        else:

            next_event = rev[i-1]

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


    return result
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
