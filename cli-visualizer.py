import argparse
import datetime
import shutil
import sqlite3
import sys
import yaml


with open("config.yaml") as f:
    config = yaml.safe_load(f)


DB = config.get("database", "onionwatcher.db")
UPTIME_DAYS = config.get("uptime_days", 7)


# ----------------------------------------------------------------------
# Database
# ----------------------------------------------------------------------

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def services():
    conn = db()

    rows = conn.execute("""
        SELECT
            services.*,
            service_state.status
        FROM services
        JOIN service_state
            ON services.id = service_state.service_id
        ORDER BY services.name
    """).fetchall()

    conn.close()
    return rows


def events(service_id):
    conn = db()

    rows = conn.execute("""
        SELECT *
        FROM events
        WHERE service_id = ?
        ORDER BY timestamp ASC
    """, (service_id,)).fetchall()

    conn.close()
    return rows


# ----------------------------------------------------------------------
# Uptime calculation
# ----------------------------------------------------------------------

def uptime_data(service_id):
    now = datetime.datetime.utcnow()
    start = now - datetime.timedelta(days=UPTIME_DAYS)

    ev = events(service_id)

    hours = UPTIME_DAYS * 24

    if not ev:
        return 0.0, ["offline"] * hours

    # Determine the state at the beginning of the uptime window.
    state = "unknown"

    for e in ev:
        t = datetime.datetime.fromisoformat(e["timestamp"])

        if t <= start:
            state = e["new_status"]
        else:
            break

    # Calculate total downtime.
    offline_seconds = 0

    if state == "offline":
        offline_start = start
    else:
        offline_start = None

    for e in ev:
        t = datetime.datetime.fromisoformat(e["timestamp"])

        if t <= start:
            continue

        if t > now:
            break

        new_state = e["new_status"]

        if new_state == "offline" and state != "offline":
            state = "offline"
            offline_start = t

        elif new_state == "online" and state == "offline":
            offline_seconds += (
                t - offline_start
            ).total_seconds()

            state = "online"
            offline_start = None

    if state == "offline" and offline_start is not None:
        offline_seconds += (
            now - offline_start
        ).total_seconds()

    total_seconds = (now - start).total_seconds()

    uptime = max(
        0.0,
        min(
            100.0,
            100.0 * (total_seconds - offline_seconds)
            / total_seconds
        )
    )

    # ------------------------------------------------------------------
    # Generate one block per hour.
    # ------------------------------------------------------------------

    blocks = []

    for i in range(hours):
        a = start + datetime.timedelta(hours=i)
        b = min(
            a + datetime.timedelta(hours=1),
            now
        )

        # Find state at beginning of this hour.
        block_state = "unknown"

        for e in ev:
            t = datetime.datetime.fromisoformat(e["timestamp"])

            if t <= a:
                block_state = e["new_status"]
            else:
                break

        cursor = a
        offline_time = 0.0

        for e in ev:
            t = datetime.datetime.fromisoformat(e["timestamp"])

            if t <= a:
                continue

            if t >= b:
                break

            if block_state == "offline":
                offline_time += (
                    t - cursor
                ).total_seconds()

            block_state = e["new_status"]
            cursor = t

        if block_state == "offline":
            offline_time += (
                b - cursor
            ).total_seconds()

        blocks.append(
            "offline" if offline_time > 0 else "online"
        )

    return uptime, blocks


# ----------------------------------------------------------------------
# Terminal output
# ----------------------------------------------------------------------

ANSI_GREEN = "\033[32m"
ANSI_RED = "\033[31m"
ANSI_RESET = "\033[0m"

BAR_CHAR = "█"


def terminal_width():
    return shutil.get_terminal_size(
        fallback=(120, 24)
    ).columns


def uptime_bar(blocks, width):
    if not blocks:
        return ""

    # Use the entire available terminal width.
    #
    # Map the hourly uptime data onto the terminal width. If there
    # are fewer hours than terminal columns, blocks are expanded.
    # If there are more hours, several hours are represented by one
    # character.

    result = []

    for x in range(width):
        start = int(x * len(blocks) / width)
        end = int((x + 1) * len(blocks) / width)

        if end <= start:
            end = start + 1

        section = blocks[start:end]

        if any(b == "offline" for b in section):
            result.append("offline")
        else:
            result.append("online")

    return result


def print_service(service, name_width):
    uptime, blocks = uptime_data(service["id"])

    width = terminal_width()
    status = service["status"].upper()

    print(
        f"{service['name']:<{name_width}} "
        f"{status:<7} "
        f"{uptime:7.2f}%   "
        f"{service['host']}"
    )

    bar = uptime_bar(blocks, width)

    output = []

    for block in bar:
        if block == "online":
            output.append(
                f"{ANSI_GREEN}{BAR_CHAR}{ANSI_RESET}"
            )
        else:
            output.append(
                f"{ANSI_RED}{BAR_CHAR}{ANSI_RESET}"
            )

    print("".join(output))
    print()

def print_dashboard():
    svcs = services()

    if not svcs:
        print("No services found.")
        return 1

    name_width = max(
        len(s["name"])
        for s in svcs
    )

    for service in svcs:
        print_service(
            service,
            name_width
        )

    return 0

# ----------------------------------------------------------------------
# CLI status command
# ----------------------------------------------------------------------

def service_status(service_name):
    conn = db()

    row = conn.execute("""
        SELECT service_state.status
        FROM services
        JOIN service_state
            ON services.id = service_state.service_id
        WHERE services.name = ?
    """, (service_name,)).fetchone()

    conn.close()

    if row is None:
        return 2

    if row["status"] == "online":
        print("1")
    else:
        print("0")

    return 0


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="OnionWatcher CLI"
    )

    subparsers = parser.add_subparsers(
        dest="command"
    )

    status_parser = subparsers.add_parser(
        "status",
        help="Return 1 if a service is online, otherwise 0"
    )

    status_parser.add_argument(
        "service",
        help="Service name"
    )

    args = parser.parse_args()

    if args.command == "status":
        return service_status(args.service)

    return print_dashboard()


if __name__ == "__main__":
    sys.exit(main())
