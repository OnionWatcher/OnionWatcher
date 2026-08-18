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

    # Services without any state history are not assumed online.
    # Fill the entire configured period as offline until the first event.
    if not ev:
        return 0, ["red"] * hours

    for i in range(hours):
        a = start + datetime.timedelta(hours=i)
        b = a + datetime.timedelta(hours=1)

        failed = False

        for e in ev:
            t = datetime.datetime.fromisoformat(e["timestamp"])
            if a <= t <= b and e["new_status"] == "offline":
                failed = True

        blocks.append("red" if failed else "green")

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
    height:4em;
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
    result = ""

    for e in reversed(events(id)):
        color = "#00ff66" if e["new_status"] == "online" else "#cc3333"
        result += f'<div style="color:{color};">{e["timestamp"]}</div>'

    return result


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
