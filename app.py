"""
NIDS v2 - Network Intrusion Detection System

Features:
- Rule-based intrusion detection
- Software-based network traffic simulation
- SQLite alert and blocked-IP storage
- Admin and analyst roles
- Automatic simulated traffic blocking
- Attack simulation
- CSV export
- Security report
- Optional email notifications
- Login and logout

Run:
    pip install -r requirements.txt
    python app.py

Open:
    http://127.0.0.1:5000

Admin:
    Username: admin
    Password: admin123

Analyst:
    Username: analyst
    Password: analyst123

Email configuration (optional):
    SENDER_EMAIL
    SENDER_PASSWORD
    ALERT_RECEIVER
"""

import csv
import io
import os
import random
import re
import smtplib
import sqlite3
import threading
import time

from collections import Counter, defaultdict, deque
from datetime import datetime
from email.message import EmailMessage
from functools import wraps

from flask import (
    Flask,
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)


# ==========================================================
# FLASK CONFIGURATION
# ==========================================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "change-me-in-production"
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False  # Set True when deployed behind HTTPS.


@app.after_request
def prevent_authenticated_page_caching(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# ==========================================================
# USER ACCOUNTS AND ROLES
# ==========================================================

USERS = {
    "admin": ("admin123", "admin"),
    "analyst": ("analyst123", "analyst"),
}

VALID_ROLES = {"admin", "analyst"}

# Demo profile information displayed in the dashboard.
PROFILES = {
    "admin": {
        "full_name": "NIDS Administrator",
        "job_title": "Security Operations Administrator",
        "email": "admin@nids.local",
        "department": "Security Operations Center",
        "team": "Network Defense",
        "phone": "Not provided",
        "location": "Local deployment",
        "account_type": "Administrator",
        "description": "Manages detection rules, simulated blocking, reports and system settings."
    },
    "analyst": {
        "full_name": "NIDS Security Analyst",
        "job_title": "Security Monitoring Analyst",
        "email": "analyst@nids.local",
        "department": "Security Operations Center",
        "team": "Threat Monitoring",
        "phone": "Not provided",
        "location": "Local deployment",
        "account_type": "Read-only Analyst",
        "description": "Monitors network events, reviews alerts and generates security reports."
    }
}


# ==========================================================
# EMAIL CONFIGURATION
# ==========================================================

SENDER = os.environ.get("SENDER_EMAIL")
PASSWORD = os.environ.get("SENDER_PASSWORD")

RECEIVER = os.environ.get(
    "ALERT_RECEIVER",
    SENDER
)


# ==========================================================
# ATTACK SEVERITY
# ==========================================================

SEVERITY = {
    "DDoS Attack": "Critical",
    "SQL Injection": "High",
    "Port Scan": "Medium",
    "XSS Attack": "Medium",
    "Brute Force": "Low",
}


RULES = {
    attack: True
    for attack in SEVERITY
}

AUTOBLOCK = [True]


# ==========================================================
# ATTACK DETECTION PATTERNS
# ==========================================================

SQLI = re.compile(
    r"(union\s+select|'\s*or\s*'?1'?\s*=\s*'?1|;\s*drop\s+table|--\s*$)",
    re.I
)

XSS = re.compile(
    r"(<script|onerror\s*=|javascript:)",
    re.I
)


# ==========================================================
# THREADING AND DATABASE CONFIGURATION
# ==========================================================

lock = threading.RLock()

DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "nids.db"
)

DB = sqlite3.connect(
    DB_PATH,
    check_same_thread=False
)

DB.row_factory = sqlite3.Row


with lock:
    DB.executescript(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT,
            type TEXT,
            src TEXT,
            dst TEXT,
            severity TEXT,
            action TEXT,
            detail TEXT
        );

        CREATE TABLE IF NOT EXISTS blocked (
            ip TEXT PRIMARY KEY,
            reason TEXT,
            time TEXT
        );

        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS user_activity (
            username TEXT PRIMARY KEY,
            last_login TEXT
        );
        """
    )

    DB.commit()

    DB.execute(
        "INSERT OR IGNORE INTO app_settings (key, value) VALUES (?, ?)",
        ("refresh_interval", "2000")
    )
    DB.execute(
        "INSERT OR IGNORE INTO app_settings (key, value) VALUES (?, ?)",
        ("browser_notifications", "true")
    )
    DB.execute(
        "INSERT OR IGNORE INTO app_settings (key, value) VALUES (?, ?)",
        ("email_notifications", "true")
    )
    DB.commit()
# ==========================================================
# TRAFFIC AND DETECTION STORAGE
# ==========================================================

traffic = deque(maxlen=30)

PENDING = []

window = defaultdict(deque)

cooldown = {}

stats = Counter()


# ==========================================================
# DATABASE FUNCTIONS
# ==========================================================

def q(sql, *args):
    """Execute a SELECT query and return dictionary rows."""

    with lock:
        return [
            dict(row)
            for row in DB.execute(sql, args).fetchall()
        ]


def run(sql, *args):
    """Execute an INSERT, UPDATE or DELETE query."""

    with lock:
        DB.execute(sql, args)
        DB.commit()


def get_setting(key, default=None):

    rows = q(
        "SELECT value FROM app_settings WHERE key=?",
        key
    )

    return rows[0]["value"] if rows else default


def save_setting(key, value):

    run(
        "INSERT INTO app_settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        key,
        str(value)
    )


# Load previously blocked IP addresses.

BLOCKED = {
    row["ip"]
    for row in q("SELECT ip FROM blocked")
}


# ==========================================================
# EMAIL NOTIFICATION
# ==========================================================

def send_email(subject, body):
    """Send an email notification if SMTP is configured."""

    if not (SENDER and PASSWORD and RECEIVER):
        return (
            False,
            "Email not configured. Set SENDER_EMAIL, "
            "SENDER_PASSWORD and ALERT_RECEIVER."
        )

    try:
        message = EmailMessage()

        message["Subject"] = subject
        message["From"] = SENDER
        message["To"] = RECEIVER

        message.set_content(body)

        with smtplib.SMTP_SSL(
            "smtp.gmail.com",
            465,
            timeout=10
        ) as server:

            server.login(SENDER, PASSWORD)
            server.send_message(message)

        return True, f"Email sent to {RECEIVER}."

    except Exception as error:

        return False, f"Email failed: {error}"


# ==========================================================
# SOFTWARE-BASED NETWORK TRAFFIC GENERATION
# ==========================================================

ATTACKERS = [
    f"203.0.113.{i}"
    for i in range(10, 22)
]

TARGET = "10.0.0.5"


def pkt(src, dst, port, **kwargs):
    """Create a simulated network packet."""

    return {
        "src": src,
        "dst": dst,
        "dport": port,
        "syn": False,
        "fail": False,
        "payload": "",
        "bad": False,
        **kwargs
    }


def normal():
    """Generate normal simulated network traffic."""

    return pkt(
        f"192.168.1.{random.randint(2, 60)}",
        f"10.0.0.{random.randint(2, 9)}",
        random.choice([80, 443, 53, 8080])
    )


# ==========================================================
# ATTACK SCENARIOS
# ==========================================================

SCEN = {

    "port_scan": lambda: (
        lambda source: [
            pkt(
                source,
                TARGET,
                port,
                syn=True,
                bad=True
            )
            for port in random.sample(
                range(20, 1024),
                20
            )
        ]
    )(random.choice(ATTACKERS)),

    "ddos": lambda: (
        lambda source: [
            pkt(
                source,
                TARGET,
                80,
                syn=True,
                bad=True
            )
            for _ in range(120)
        ]
    )(random.choice(ATTACKERS)),

    "brute_force": lambda: (
        lambda source: [
            pkt(
                source,
                TARGET,
                22,
                fail=True,
                bad=True
            )
            for _ in range(10)
        ]
    )(random.choice(ATTACKERS)),

    "sqli": lambda: [
        pkt(
            random.choice(ATTACKERS),
            TARGET,
            80,
            bad=True,
            payload="GET /item?id=1' OR '1'='1"
        )
    ],

    "xss": lambda: [
        pkt(
            random.choice(ATTACKERS),
            TARGET,
            80,
            bad=True,
            payload="q=<script>alert(1)</script>"
        )
    ],
}


# ==========================================================
# ALERT GENERATION
# ==========================================================

def raise_alert(kind, packet, detail):
    """Save a security alert and optionally block its source."""

    now = time.time()

    if not RULES.get(kind, False):
        return

    cooldown_key = (
        packet["src"],
        kind
    )

    if now - cooldown.get(cooldown_key, 0) < 20:
        return

    cooldown[cooldown_key] = now

    severity = SEVERITY[kind]

    should_block = (
        AUTOBLOCK[0]
        and severity in ("Critical", "High")
    )

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    action = "Blocked" if should_block else "Logged"

    with lock:

        run(
            """
            INSERT INTO alerts
            (time, type, src, dst, severity, action, detail)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            timestamp,
            kind,
            packet["src"],
            packet["dst"],
            severity,
            action,
            detail
        )

        if should_block:

            BLOCKED.add(packet["src"])

            run(
                """
                INSERT OR IGNORE INTO blocked
                (ip, reason, time)
                VALUES (?, ?, ?)
                """,
                packet["src"],
                f"{kind}: {detail}",
                timestamp
            )

    # Critical alerts trigger an email in a background thread.

    if severity == "Critical" and get_setting(
        "email_notifications",
        "true"
    ) == "true":

        threading.Thread(
            target=send_email,
            args=(
                f"NIDS Critical Alert: {kind}",
                (
                    f"Attack: {kind}\n"
                    f"Source: {packet['src']}\n"
                    f"Destination: {packet['dst']}\n"
                    f"Time: {timestamp}\n"
                    f"Details: {detail}"
                )
            ),
            daemon=True
        ).start()
# ==========================================================
# INTRUSION DETECTION ENGINE
# ==========================================================

def inspect(packet):
    """Inspect a simulated packet against detection rules."""

    now = time.time()

    packet_window = window[packet["src"]]

    packet_window.append(
        (
            now,
            packet["dport"],
            packet["syn"],
            packet["fail"]
        )
    )

    # Retain only the last 30 seconds.

    while (
        packet_window
        and now - packet_window[0][0] > 30
    ):
        packet_window.popleft()

    # Port scan detection.

    ports = {
        destination_port
        for timestamp, destination_port, syn, failed
        in packet_window
        if now - timestamp <= 10 and syn
    }

    if len(ports) >= 15:

        raise_alert(
            "Port Scan",
            packet,
            f"{len(ports)} distinct ports probed in 10s"
        )

    # DDoS detection.

    syn_count = sum(
        1
        for timestamp, destination_port, syn, failed
        in packet_window
        if (
            now - timestamp <= 5
            and syn
            and destination_port == 80
        )
    )

    if syn_count >= 80:

        raise_alert(
            "DDoS Attack",
            packet,
            f"{syn_count} SYN packets to port 80 in 5s"
        )

    # Brute-force detection.

    failed_count = sum(
        1
        for timestamp, destination_port, syn, failed
        in packet_window
        if failed
    )

    if failed_count >= 8:

        raise_alert(
            "Brute Force",
            packet,
            f"{failed_count} failed logins in 30s"
        )

    # SQL injection detection.

    if SQLI.search(packet["payload"]):

        raise_alert(
            "SQL Injection",
            packet,
            "SQL pattern in HTTP request"
        )

    # XSS detection.

    if XSS.search(packet["payload"]):

        raise_alert(
            "XSS Attack",
            packet,
            "Script tag in HTTP request"
        )


# ==========================================================
# TRAFFIC SIMULATION THREAD
# ==========================================================

def simulate():
    """Generate normal and malicious simulated network traffic."""

    while True:

        time.sleep(1)

        batch = [
            normal()
            for _ in range(random.randint(25, 45))
        ]

        kinds = []

        while PENDING:
            kinds.append(PENDING.pop())

        if random.random() < 0.15:

            kinds.append(
                random.choice(list(SCEN))
            )

        for kind in kinds:
            batch += SCEN[kind]()

        random.shuffle(batch)

        normal_count = 0
        malicious_count = 0
        dropped_count = 0

        for packet in batch:

            if packet["src"] in BLOCKED:
                dropped_count += 1
                continue

            if packet["bad"]:
                malicious_count += 1
            else:
                normal_count += 1

            inspect(packet)

        stats["packets"] += (
            normal_count
            + malicious_count
            + dropped_count
        )

        traffic.append(
            {
                "t": datetime.now().strftime("%H:%M:%S"),
                "normal": normal_count,
                "dropped": dropped_count,
                "malicious": malicious_count
            }
        )


# ==========================================================
# AUTHENTICATION DECORATOR
# ==========================================================

def login_required(function):
    """Require a valid user and role in the session."""

    @wraps(function)
    def wrapper(*args, **kwargs):

        username = session.get("user")
        role = session.get("role")

        # Clear old or incomplete sessions.

        if (
            not username
            or role not in VALID_ROLES
            or username not in USERS
        ):

            session.clear()

            return redirect(
                url_for("login")
            )

        # Check that the stored role matches the account.

        if USERS[username][1] != role:

            session.clear()

            return redirect(
                url_for("login")
            )

        return function(*args, **kwargs)

    return wrapper


# ==========================================================
# ADMIN-ONLY DECORATOR
# ==========================================================

def admin_only(function):
    """Allow only authenticated administrators."""

    @wraps(function)
    def wrapper(*args, **kwargs):

        if session.get("role") != "admin":

            return jsonify(
                ok=False,
                message="Admin only."
            ), 403

        return function(*args, **kwargs)

    return login_required(wrapper)
# ==========================================================
# LOGIN ROUTE
# ==========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    # Already authenticated users go to dashboard.

    username = session.get("user")
    role = session.get("role")

    if (
        username in USERS
        and role in VALID_ROLES
        and USERS[username][1] == role
    ):

        return redirect(
            url_for("dashboard")
        )

    # Remove stale sessions before processing login.

    session.clear()

    error = None

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        record = USERS.get(username)

        if record and record[0] == password:

            # Start a fresh authenticated session.

            session.clear()

            session["user"] = username
            session["role"] = record[1]
            session["login_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            run(
                "INSERT INTO user_activity (username, last_login) VALUES (?, ?) "
                "ON CONFLICT(username) DO UPDATE SET last_login=excluded.last_login",
                username,
                session["login_time"]
            )

            return redirect(
                url_for("dashboard")
            )

        error = "Incorrect username or password."

    return render_template(
        "login.html",
        error=error
    )


# ==========================================================
# LOGOUT ROUTE
# ==========================================================

@app.post("/logout")
@login_required
def logout():
    """End the current authenticated session."""

    session.clear()

    response = redirect(url_for("login"))

    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, max-age=0"
    )

    response.headers["Pragma"] = "no-cache"

    return response


# ==========================================================
# DASHBOARD ROUTE
# ==========================================================

@app.route("/")
@login_required
def dashboard():

    return render_template(
        "dashboard.html",
        user=session.get("user"),
        role=session.get("role"),
        profile=PROFILES.get(session.get("user"), {}),
        login_time=session.get("login_time", "Not available")
    )


# ==========================================================
# DASHBOARD STATISTICS
# ==========================================================

def kpis():

    def count(where="1"):

        result = q(
            f"SELECT COUNT(*) AS c FROM alerts WHERE {where}"
        )

        return result[0]["c"]

    return {
        "total": count(),
        "critical": count("severity='Critical'"),
        "blocked": count("action='Blocked'"),
        "packets": stats["packets"],
        "conns": random.randint(800, 900)
    }


# ==========================================================
# DASHBOARD DATA API
# ==========================================================

@app.route("/api/data")
@login_required
def data():

    types = {
        attack: 0
        for attack in SEVERITY
    }

    results = q(
        """
        SELECT type, COUNT(*) AS c
        FROM alerts
        GROUP BY type
        """
    )

    for row in results:

        types[row["type"]] = row["c"]

    return jsonify(

        kpi=kpis(),

        traffic=list(traffic),

        types=types,

        rules=RULES,

        autoblock=AUTOBLOCK[0],

        alerts=q(
            """
            SELECT *
            FROM alerts
            ORDER BY id DESC
            LIMIT 100
            """
        ),

        blocked=q(
            """
            SELECT *
            FROM blocked
            ORDER BY time DESC
            """
        ),

        top=q(
            """
            SELECT src AS ip, COUNT(*) AS c
            FROM alerts
            GROUP BY src
            ORDER BY c DESC
            LIMIT 5
            """
        ),

        email=bool(
            SENDER and PASSWORD and RECEIVER
        ),

        role=session.get("role", "analyst"),

        settings={
            "refresh_interval": int(
                get_setting("refresh_interval", "2000")
            ),
            "browser_notifications": (
                get_setting("browser_notifications", "true") == "true"
            ),
            "email_notifications": (
                get_setting("email_notifications", "true") == "true"
            )
        },

        profile=PROFILES.get(
            session.get("user"),
            {}
        ),

        login_time=session.get(
            "login_time",
            "Not available"
        )
    )


# ==========================================================
# TOGGLE DETECTION RULE
# ==========================================================

@app.post("/api/rules/<name>")
@admin_only
def toggle_rule(name):

    if name not in RULES:

        return jsonify(
            ok=False,
            message="Unknown detection rule."
        ), 404

    RULES[name] = not RULES[name]

    return jsonify(
        ok=True,
        rule=name,
        enabled=RULES[name]
    )


# ==========================================================
# TOGGLE AUTOMATIC BLOCKING
# ==========================================================

@app.post("/api/autoblock")
@admin_only
def autoblock():

    AUTOBLOCK[0] = not AUTOBLOCK[0]

    return jsonify(
        ok=True,
        enabled=AUTOBLOCK[0]
    )


# ==========================================================
# UNBLOCK AN IP ADDRESS
# ==========================================================

@app.post("/api/unblock/<ip>")
@admin_only
def unblock(ip):

    BLOCKED.discard(ip)

    run(
        "DELETE FROM blocked WHERE ip=?",
        ip
    )

    return jsonify(
        ok=True,
        message=f"{ip} removed from the simulated blocklist."
    )


# ==========================================================
# SIMULATE AN ATTACK
# ==========================================================

@app.post("/api/simulate/<kind>")
@admin_only
def sim(kind):

    if kind not in SCEN:

        return jsonify(
            ok=False,
            message="Unknown attack scenario."
        ), 404

    PENDING.append(kind)

    return jsonify(
        ok=True,
        message=f"{kind} simulation queued."
    )


# ==========================================================
# TEST EMAIL
# ==========================================================

@app.post("/api/test-email")
@admin_only
def test_email():

    success, message = send_email(
        "[NIDS] Test alert",
        "This is a test alert from your NIDS dashboard."
    )

    return jsonify(
        ok=success,
        message=message
    )


# ==========================================================
# USER SETTINGS
# ==========================================================

@app.post("/api/settings")
@login_required
def update_settings():

    payload = request.get_json(silent=True) or {}

    try:

        refresh_interval = int(
            payload.get("refresh_interval", 2000)
        )

    except (TypeError, ValueError):

        return jsonify(
            ok=False,
            message="Invalid refresh interval."
        ), 400

    if refresh_interval not in (2000, 5000, 10000):

        return jsonify(
            ok=False,
            message="Choose 2, 5 or 10 seconds."
        ), 400

    browser_notifications = bool(
        payload.get("browser_notifications", False)
    )

    email_notifications = bool(
        payload.get("email_notifications", False)
    )

    save_setting(
        "refresh_interval",
        refresh_interval
    )

    save_setting(
        "browser_notifications",
        str(browser_notifications).lower()
    )

    save_setting(
        "email_notifications",
        str(email_notifications).lower()
    )

    return jsonify(
        ok=True,
        message="Settings saved successfully.",
        settings={
            "refresh_interval": refresh_interval,
            "browser_notifications": browser_notifications,
            "email_notifications": email_notifications
        }
    )


# ==========================================================
# CSV EXPORT
# ==========================================================

@app.route("/export/csv")
@login_required
def export_csv():

    output = io.StringIO()

    writer = csv.writer(output)

    writer.writerow(
        [
            "Time",
            "Type",
            "Source IP",
            "Destination IP",
            "Severity",
            "Action",
            "Detail"
        ]
    )

    alerts = q(
        """
        SELECT *
        FROM alerts
        ORDER BY id DESC
        """
    )

    for alert in alerts:

        writer.writerow(
            [
                alert["time"],
                alert["type"],
                alert["src"],
                alert["dst"],
                alert["severity"],
                alert["action"],
                alert["detail"]
            ]
        )

    return Response(

        output.getvalue(),

        mimetype="text/csv",

        headers={
            "Content-Disposition":
            "attachment; filename=nids_alerts.csv"
        }

    )


# ==========================================================
# SECURITY REPORT
# ==========================================================

@app.route("/report")
@login_required
def report():

    statistics = kpis()

    return render_template(

        "report.html",

        alerts=q(
            """
            SELECT *
            FROM alerts
            ORDER BY id DESC
            """
        ),

        now=datetime.now().strftime(
            "%d %b %Y %H:%M"
        ),

        stats={
            "total": statistics["total"],
            "blocked": statistics["blocked"],
            "Critical": statistics["critical"]
        }

    )


# ==========================================================
# APPLICATION START
# ==========================================================

if __name__ == "__main__":

    # Start the simulator only when running this file directly.

    simulation_thread = threading.Thread(
        target=simulate,
        daemon=True
    )

    simulation_thread.start()

    print("=" * 55)
    print("SMART NETWORK INTRUSION DETECTION SYSTEM")
    print("=" * 55)
    print("Traffic simulation started.")
    print("Dashboard: http://127.0.0.1:5000")
    print("Admin login: admin / admin123")
    print("Analyst login: analyst / analyst123")
    print("=" * 55)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )