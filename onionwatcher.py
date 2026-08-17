#!/usr/bin/env python3

import os
import glob
import yaml
import time
import random
import sqlite3
import socket
import socks
import requests

from collections import deque
from datetime import datetime


# ==========================================================
# Helpers
# ==========================================================

def timestamp():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def log(message):
    print(f"[{timestamp()}] {message}", flush=True)


# ==========================================================
# Configuration
# ==========================================================

def load_config():

    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)


# ==========================================================
# Database
# ==========================================================

class Database:

    def __init__(self, filename):

        self.conn = sqlite3.connect(
            filename,
            check_same_thread=False
        )

        self.conn.row_factory = sqlite3.Row

        self.create_tables()


    def create_tables(self):

        self.conn.executescript("""

        CREATE TABLE IF NOT EXISTS services (

            id INTEGER PRIMARY KEY,

            name TEXT UNIQUE NOT NULL,

            host TEXT NOT NULL,

            port INTEGER NOT NULL,

            type TEXT NOT NULL,

            path TEXT DEFAULT '/'

        );


        CREATE TABLE IF NOT EXISTS service_state (

            service_id INTEGER PRIMARY KEY,

            status TEXT NOT NULL DEFAULT 'unknown',

            failures INTEGER NOT NULL DEFAULT 0,

            FOREIGN KEY(service_id)
                REFERENCES services(id)

        );


        CREATE TABLE IF NOT EXISTS events (

            id INTEGER PRIMARY KEY,

            service_id INTEGER,

            old_status TEXT,

            new_status TEXT,

            timestamp TEXT,

            FOREIGN KEY(service_id)
                REFERENCES services(id)

        );

        """)

        self.conn.commit()


    def sync_services(self, services):

        config_hosts = set()
        config_names = set()

        for service in services:
            config_hosts.add(service["address"])
            config_names.add(service["name"])

            row = self.conn.execute(
                """
                SELECT id FROM services
                WHERE host=? OR name=?
                """,
                (
                    service["address"],
                    service["name"]
                )
            ).fetchone()


            if row:
                self.conn.execute(
                    """
                    UPDATE services
                    SET name=?,
                        host=?,
                        port=?,
                        type=?,
                        path=?
                    WHERE id=?
                    """,
                    (
                        service["name"],
                        service["address"],
                        service.get("port", 80),
                        service["type"],
                        service.get("path", "/"),
                        row["id"]
                    )
                )

            else:
                cur = self.conn.execute(
                    """
                    INSERT INTO services
                    (name,host,port,type,path)
                    VALUES (?,?,?,?,?)
                    """,
                    (
                        service["name"],
                        service["address"],
                        service.get("port", 80),
                        service["type"],
                        service.get("path", "/")
                    )
                )

                self.conn.execute(
                    """
                    INSERT INTO service_state
                    (service_id)
                    VALUES (?)
                    """,
                    (
                        cur.lastrowid,
                    )
                )


        # Remove services that no longer exist in configuration
        placeholders = ",".join("?" for _ in config_hosts)

        if config_hosts:
            self.conn.execute(
                f"""
                DELETE FROM service_state
                WHERE service_id IN (
                    SELECT id FROM services
                    WHERE host NOT IN ({placeholders})
                )
                """,
                tuple(config_hosts)
            )

            self.conn.execute(
                f"""
                DELETE FROM events
                WHERE service_id NOT IN (
                    SELECT id FROM services
                )
                """
            )

            self.conn.execute(
                f"""
                DELETE FROM services
                WHERE host NOT IN ({placeholders})
                """,
                tuple(config_hosts)
            )

        else:
            # Empty config means remove everything
            self.conn.execute(
                "DELETE FROM service_state"
            )
            self.conn.execute(
                "DELETE FROM events"
            )
            self.conn.execute(
                "DELETE FROM services"
            )


        self.conn.commit()


    def get_services(self):

        return self.conn.execute(
            """
            SELECT
                services.*,
                service_state.status,
                service_state.failures

            FROM services

            JOIN service_state
            ON services.id=service_state.service_id

            ORDER BY services.id
            """
        ).fetchall()



    def state(self, service_id):

        return self.conn.execute(
            """
            SELECT *
            FROM service_state
            WHERE service_id=?
            """,
            (
                service_id,
            )
        ).fetchone()



    def increase_failure(self, service_id):

        self.conn.execute(
            """
            UPDATE service_state
            SET failures = failures + 1
            WHERE service_id=?
            """,
            (
                service_id,
            )
        )

        self.conn.commit()



    def reset_failures(self, service_id):

        self.conn.execute(
            """
            UPDATE service_state
            SET failures=0
            WHERE service_id=?
            """,
            (
                service_id,
            )
        )

        self.conn.commit()



    def set_status(self, service_id, new_status):

        current = self.state(service_id)

        old_status = current["status"]


        if old_status == new_status:
            return


        self.conn.execute(
            """
            UPDATE service_state
            SET status=?,
                failures=0
            WHERE service_id=?
            """,
            (
                new_status,
                service_id
            )
        )


        self.conn.execute(
            """
            INSERT INTO events
            (
                service_id,
                old_status,
                new_status,
                timestamp
            )
            VALUES (?,?,?,?)
            """,
            (
                service_id,
                old_status,
                new_status,
                timestamp()
            )
        )

        self.conn.commit()


        log(
            f"STATE CHANGE: "
            f"{old_status.upper()} -> {new_status.upper()}"
        )



# ==========================================================
# YAML service loader
# ==========================================================

def load_services(directory):

    services = []

    files = (
        glob.glob(
            os.path.join(directory, "*.yaml")
        )
        +
        glob.glob(
            os.path.join(directory, "*.yml")
        )
    )


    for filename in files:

        with open(filename) as f:

            data = yaml.safe_load(f)


        if not data:
            continue


        for service in data.get("services", []):

            service.setdefault(
                "port",
                80
            )

            service.setdefault(
                "path",
                "/"
            )

            services.append(service)


    return services



# ==========================================================
# Probers
# ==========================================================

class Prober:

    def __init__(self, proxy):

        self.session = requests.Session()

        self.session.proxies = {
            "http": proxy,
            "https": proxy
        }



    def new_circuit(self):
        try:
            from stem import Signal
            from stem.control import Controller

            with Controller.from_port(port=9051) as controller:
                controller.authenticate()

                controller.signal(Signal.NEWNYM)

                log("Requested new Tor circuit")

                time.sleep(3)

                for circuit in controller.get_circuits():
                    if circuit.status == "BUILT":
                        path = []

                        for relay, _ in circuit.path:
                            path.append(relay)

                        if path:
                            log(
                                "New Tor circuit: "
                                + " -> ".join(path)
                            )

                        break

                return True

        except Exception as e:
            log(
                f"Tor circuit change failed: {e}"
            )

            return False


    def probe(self, service):

        if service["type"] == "http":

            return self.http(service)


        if service["type"] == "tcp":

            return self.tcp(service)


        log(
            f"Unknown service type: {service['type']}"
        )

        return False



    def http(self, service):

        url = (
            f"http://{service['host']}:"
            f"{service['port']}"
            f"{service['path']}"
        )

        try:

            response = self.session.get(
                url,
                timeout=30
            )

            return response.status_code < 500


        except Exception:

            return False



    def tcp(self, service):

        try:

            s = socks.socksocket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            proxy_host = (
                self.session.proxies["http"]
                .replace("socks5h://", "")
                .split(":")
            )


            s.set_proxy(
                socks.SOCKS5,
                proxy_host[0],
                int(proxy_host[1]),
                rdns=True
            )


            s.settimeout(30)


            s.connect(
                (
                    service["host"],
                    service["port"]
                )
            )


            s.close()

            return True


        except Exception:

            return False



# ==========================================================
# Main
# ==========================================================

def main():

    config = load_config()


    db = Database(
        config.get(
            "database",
            "onionwatcher.db"
        )
    )


    yaml_services = load_services(
        config.get(
            "services_directory",
            "services"
        )
    )


    db.sync_services(
        yaml_services
    )


    services = list(
        db.get_services()
    )


    normal_queue = deque(
        services
    )

    retry_queue = deque()


    prober = Prober(
        config.get(
            "tor_proxy",
            "socks5h://127.0.0.1:9050"
        )
    )


    max_failures = config.get(
        "failures_before_offline",
        3
    )


    interval = config.get(
        "probe_interval",
        60
    )


    jitter = config.get(
        "jitter_seconds",
        10
    )


    log(
        f"Loaded {len(services)} services"
    )


    while True:


        # -------------------------------
        # Normal queue
        # -------------------------------

        service = normal_queue.popleft()

        normal_queue.append(service)


        log(
            f"Checking {service['name']} "
            f"({service['host']}:{service['port']})"
        )


        ok = prober.probe(service)


        if ok:

            log("Result: ONLINE")

            db.reset_failures(
                service["id"]
            )

            db.set_status(
                service["id"],
                "online"
            )


        else:

            log("Result: FAILED")


            db.increase_failure(
                service["id"]
            )


            state = db.state(
                service["id"]
            )


            if state["status"] == "online":

                if state["failures"] >= max_failures:

                    db.set_status(
                        service["id"],
                        "offline"
                    )

                    log(
                        "Certified OFFLINE"
                    )

                else:

                    prober.new_circuit()

                    retry_queue.append(service)

                    log(
                        f"Added retry "
                        f"({state['failures']}/{max_failures})"
                    )


        checked_id = service["id"]



        # -------------------------------
        # Retry queue
        # -------------------------------

        if retry_queue:

            retry_service = retry_queue[0]

            if retry_service["id"] != checked_id:

                retry_service = retry_queue.popleft()

                log(
                    f"Retrying {retry_service['name']}"
                )


                ok = prober.probe(
                    retry_service
                )


                if ok:

                    log(
                        "Retry succeeded"
                    )

                    db.reset_failures(
                        retry_service["id"]
                    )


                else:

                    log(
                        "Retry failed"
                    )

                    db.increase_failure(
                        retry_service["id"]
                    )


                    state = db.state(
                        retry_service["id"]
                    )


                    if state["failures"] >= max_failures:

                        db.set_status(
                            retry_service["id"],
                            "offline"
                        )

                        log(
                            "Certified OFFLINE"
                        )

                    else:

                        prober.new_circuit()

                        retry_queue.append(
                            retry_service
                        )


            else:

                log(
                    "Skipping duplicate retry in same cycle"
                )



        sleep_time = (
            interval
            +
            random.randint(
                -jitter,
                jitter
            )
        )


        log(
            f"Sleeping {sleep_time} seconds"
        )


        time.sleep(
            max(1, sleep_time)
        )



if __name__ == "__main__":
    main()
