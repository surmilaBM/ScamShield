
from flask import Flask, render_template, request, redirect, url_for
import joblib
import re
import sqlite3
import ipaddress
from pathlib import Path
from datetime import datetime
from urllib.parse import urlsplit, unquote

app = Flask(__name__)
SHOW_URL_SCANNER = True
@app.context_processor
def inject_feature_flags():
    return {"SHOW_URL_SCANNER": SHOW_URL_SCANNER}

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "scans.db"
MODEL_PATH = BASE_DIR / "scam_model.joblib"

model = joblib.load(MODEL_PATH)


def get_db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_db() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message TEXT NOT NULL,
                status TEXT NOT NULL,
                score INTEGER NOT NULL,
                warnings TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS url_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                status TEXT NOT NULL,
                score INTEGER NOT NULL,
                warnings TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)



def get_warnings(message):
    text = message.lower()
    warnings = []

    checks = {
        "Urgency or pressure": [
            r"\b(urgent|immediately|blocked|suspended|disconnect|expire|act now|last chance)\b"
        ],
        "Sensitive information request": [
            r"\b(otp|pin|password|cvv|aadhaar|aadhar|verification code|recovery phrase)\b"
        ],
        "Prize or reward language": [
            r"\b(prize|winner|won|reward|processing fee|claim your|lottery)\b"
        ],
        "Suspicious link present": [
            r"https?://\S+|\bwww\.\S+"
        ],
        "Banking or account verification": [
            r"\b(upi|kyc|bank account|bank details|refund|account verification|card details)\b"
        ],
        "Upfront payment request": [
            r"\b(upfront payment|registration fee|security deposit|processing fee|pay to claim|advance fee|activation fee)\b"
        ],
        "Potential job scam": [
            r"\b(work from home|earn money|daily income|weekly income|no experience required|without an interview|guaranteed job|easy money)\b"
        ],
        "Unrealistic earnings claim": [
            r"\b(earn|earning|income|salary|profit).{0,45}\b(per day|daily|per week|weekly|in \d+ minutes|guaranteed)\b",
            r"\b(guaranteed).{0,30}\b(profit|income|earnings|returns)\b"
        ],
        "Investment offer": [
            r"\b(guaranteed returns|double your money|risk.free returns|crypto investment|investment opportunity)\b"
        ],
        "Suspicious account or identity request": [
            r"\b(share your otp|send your otp|verify your identity|enter your password|share your pin)\b"
        ],
    }

    for warning, patterns in checks.items():
        if any(re.search(pattern, text) for pattern in patterns):
            warnings.append(warning)

    return warnings



def analyze_message(message):
    prediction = model.predict([message])[0]
    probabilities = model.predict_proba([message])[0]
    classes = list(model.classes_)
    score = round(float(probabilities[classes.index("spam")]) * 100)

    warnings = get_warnings(message)

    # Consider both ML prediction and rule-based warning signals.
    high_risk_warnings = {
        "Sensitive information request",
        "Suspicious link present",
        "Upfront payment request",
        "Suspicious account or identity request",
        "Investment offer",
    }

    has_high_risk_warning = any(
        warning in high_risk_warnings for warning in warnings
    )

    if prediction == "spam" or score >= 60 or has_high_risk_warning:
        status = "Suspicious"
        explanation = (
            "This message has patterns that may indicate a scam. "
            "Review the warning signals carefully before taking action."
        )
    elif score >= 35 or len(warnings) >= 2:
        status = "Needs caution"
        explanation = (
            "This message contains some potentially risky patterns. "
            "Verify the sender independently before trusting it."
        )
    else:
        status = "Likely legitimate"
        explanation = (
            "The model found fewer spam indicators in this message. "
            "This does not guarantee that the message is safe."
        )

    return {
        "status": status,
        "score": score,
        "warnings": warnings,
        "explanation": explanation,
    }



def save_scan(message, result):
    with get_db() as connection:
        cursor = connection.execute("""
            INSERT INTO scans
                (message, status, score, warnings, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            message,
            result["status"],
            result["score"],
            "|||".join(result["warnings"]),
            datetime.now().astimezone().isoformat(timespec="seconds"),
        ))
        return cursor.lastrowid


def fetch_scans(limit=100):
    with get_db() as connection:
        rows = connection.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()

    scans = []
    for row in rows:
        scan = dict(row)
        scan["warnings"] = (
            scan["warnings"].split("|||") if scan["warnings"] else []
        )
        scans.append(scan)

    return scans



def analyze_url(raw_url):
    """Analyze URL structure without contacting the submitted website."""
    import ipaddress
    from urllib.parse import urlsplit, unquote

    value = raw_url.strip()

    if not value or len(value) > 2048:
        return {
            "status": "Invalid URL",
            "score": 0,
            "warnings": ["Enter a URL under 2,048 characters."],
            "explanation": "The supplied URL is empty or too long.",
        }

    if not re.match(r"^https?://", value, re.IGNORECASE):
        return {
            "status": "Invalid URL",
            "score": 0,
            "warnings": ["URL must begin with http:// or https://"],
            "explanation": "Enter a complete HTTP or HTTPS URL.",
        }

    warnings = []
    score = 0

    def flag(message, points):
        nonlocal score
        if message not in warnings:
            warnings.append(message)
            score += points

    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname

        # Force validation of malformed port numbers.
        _ = parsed.port

        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Unsupported scheme")

        if not hostname or any(c.isspace() for c in hostname):
            raise ValueError("Invalid hostname")

        host = hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except (ValueError, UnicodeError):
        return {
            "status": "Invalid URL",
            "score": 0,
            "warnings": ["Malformed URL structure"],
            "explanation": "The URL could not be parsed. No network request was made.",
        }

    if parsed.username is not None or parsed.password is not None:
        flag("Username or password embedded in URL", 25)

    try:
        ipaddress.ip_address(host)
        flag("IP address used instead of a domain name", 30)
    except ValueError:
        pass

    if "xn--" in host:
        flag("Internationalized or punycode hostname", 20)

    if len(host) > 50:
        flag("Unusually long hostname", 10)

    if host.count("-") >= 3:
        flag("Multiple hyphens in hostname", 10)

    labels = host.split(".")
    if len(labels) >= 5:
        flag("Deeply nested subdomains", 10)

    if parsed.scheme.lower() == "http":
        flag("Connection does not use HTTPS", 10)

    # A trusted-looking name in a subdomain is not the registered domain.
    known_brands = {
        "google", "paypal", "amazon", "microsoft", "apple",
        "facebook", "instagram", "whatsapp", "netflix",
        "sbi", "hdfc", "icici", "axisbank", "paytm",
        "phonepe", "gpay", "googlepay", "irctc", "uidai",
        "indiapost", "fedex", "dhl"
    }

    # This is a conservative heuristic, not a public-suffix-list parser.
    registered_name = labels[-2] if len(labels) >= 2 else labels[0]
    brand_words = set(re.findall(r"[a-z0-9]+", host))

    for brand in sorted(known_brands):
        if brand in brand_words and registered_name != brand:
            flag(
                f"Brand-like name '{brand}' appears outside the main domain",
                25
            )
            break

    # Check for a brand word inside a longer hostname label.
    for brand in sorted(known_brands):
        if any(
            brand in label and label != brand
            for label in labels[:-1]
        ):
            flag("Possible brand impersonation in hostname", 20)
            break

    shorteners = {
        "bit.ly", "tinyurl.com", "t.co", "is.gd",
        "cutt.ly", "shorturl.at", "rb.gy"
    }
    if host in shorteners:
        flag("URL shortener hides the final destination", 15)

    decoded_path = unquote(parsed.path).lower()
    decoded_query = unquote(parsed.query).lower()
    path_query = decoded_path + "?" + decoded_query

    sensitive_terms = (
        "login", "verify", "verification", "password", "account",
        "wallet", "banking", "signin", "confirm", "otp", "kyc"
    )
    if any(term in path_query for term in sensitive_terms):
        flag("Path or query contains account-related terms", 10)

    if re.search(r"%[0-9a-fA-F]{2}", parsed.path + parsed.query):
        flag("Percent-encoded characters in path or query", 5)

    if "@" in value.split("://", 1)[-1].split("/", 1)[0]:
        flag("At-sign in URL authority may disguise the destination", 15)

    score = min(score, 100)

    if score >= 50:
        status = "High structural risk"
    elif score >= 20:
        status = "Some suspicious signals"
    else:
        status = "Low structural risk"

    explanation = (
        "Multiple structural warning rules were triggered. Review the "
        "indicators carefully; this is not proof that the site is malicious."
        if warnings else
        "No configured warning rules were triggered. This does not prove "
        "that the website is legitimate or safe."
    )

    return {
        "status": status,
        "score": score,
        "warnings": warnings,
        "explanation": explanation,
    }



def save_url_scan(url, result):
    with get_db() as connection:
        cursor = connection.execute("""
            INSERT INTO url_scans
                (url, status, score, warnings, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            url,
            result["status"],
            result["score"],
            "|||".join(result["warnings"]),
            datetime.now().astimezone().isoformat(timespec="seconds"),
        ))
        return cursor.lastrowid




@app.route("/")
def dashboard():
    with get_db() as connection:
        message_scans = connection.execute(
            """
            SELECT id, message AS content, status, score, created_at,
               'message' AS scan_type
            FROM scans
            """
        ).fetchall()

        url_scans = connection.execute(
            """
            SELECT id, url AS content, status, score, created_at,
               'url' AS scan_type
            FROM url_scans
            """
        ).fetchall()

        scans = sorted(
        list(message_scans) + list(url_scans),
        key=lambda scan: scan["created_at"] or "",
         reverse=True,
        )[:5]

    with get_db() as connection:
        message_total = connection.execute(
            "SELECT COUNT(*) FROM scans"
        ).fetchone()[0]

        url_total = connection.execute(
            "SELECT COUNT(*) FROM url_scans"
        ).fetchone()[0]

        total = message_total + url_total

        message_flagged = connection.execute(
            "SELECT COUNT(*) FROM scans WHERE status = 'Suspicious'"
        ).fetchone()[0]

        url_flagged = connection.execute(
            """
            SELECT COUNT(*) FROM url_scans
            WHERE status IN (
                'High structural risk',
                'Some suspicious signals'
            )
            """
        ).fetchone()[0]

        flagged = message_flagged + url_flagged

        message_warning_rows = connection.execute(
            """
            SELECT warnings
            FROM scans
            WHERE status = 'Suspicious'
              AND warnings IS NOT NULL
              AND warnings != ''
            """
        ).fetchall()

        url_warning_rows = connection.execute(
            """
            SELECT warnings
            FROM url_scans
            WHERE status IN (
                'High structural risk',
                'Some suspicious signals'
            )
              AND warnings IS NOT NULL
              AND warnings != ''
            """
        ).fetchall()

    warning_counts = {}

    for row in list(message_warning_rows) + list(url_warning_rows):
        for warning in row["warnings"].split("|||"):
            warning = warning.strip()
            if warning:
                warning_counts[warning] = warning_counts.get(warning, 0) + 1

    most_common_warning = (
        max(warning_counts, key=warning_counts.get)
        if warning_counts
        else "None yet"
    )

    return render_template(
        "dashboard.html",
        active_page="dashboard",
        recent_scans=scans,
        total_scans=total,
        flagged_scans=flagged,
        most_common_warning=most_common_warning,
    )


@app.route("/analyzer", methods=["GET", "POST"])
def analyzer():
    result = None
    message = ""

    if request.method == "POST":
        message = request.form.get("message", "").strip()

        if message:
            result = analyze_message(message)
            result["scan_id"] = save_scan(message, result)
        else:
            result = {
                "status": "No message entered",
                "score": 0,
                "warnings": [],
                "explanation": "Paste a message before running the analysis.",
            }

    return render_template(
        "index.html",
        result=result,
        message=message,
        active_page="analyzer",
    )


@app.route("/url-scanner", methods=["GET", "POST"])
def url_scanner():
    result = None
    submitted_url = ""

    if request.method == "POST":
        submitted_url = request.form.get("url", "").strip()

        if submitted_url:
            result = analyze_url(submitted_url)
            result["scan_id"] = save_url_scan(submitted_url, result)
        else:
            result = {
                "status": "Invalid URL",
                "score": 0,
                "warnings": ["Enter a URL to analyze."],
                "explanation": "No URL was provided.",
            }

    with get_db() as connection:
        recent_url_scans = connection.execute("""
            SELECT * FROM url_scans ORDER BY id DESC LIMIT 5
        """).fetchall()

    recent_url_scans = [
        {
            **dict(row),
            "warnings": row["warnings"].split("|||") if row["warnings"] else [],
        }
        for row in recent_url_scans
    ]

    return render_template(
        "url_scanner.html",
        active_page="url_scanner",
        result=result,
        submitted_url=submitted_url,
        recent_url_scans=recent_url_scans,
    )



@app.route("/history")
def history():
    scans = fetch_scans(100)

    with get_db() as connection:
        url_rows = connection.execute(
            "SELECT * FROM url_scans ORDER BY id DESC LIMIT 100"
        ).fetchall()

    url_scans = [
        {
            **dict(row),
            "warnings": row["warnings"].split("|||")
            if row["warnings"] else [],
        }
        for row in url_rows
    ]

    return render_template(
        "history.html",
        scans=scans,
        url_scans=url_scans,
        active_page="history",
    )



@app.route("/insights")

@app.route("/insights")
def insights():
    with get_db() as connection:
        message_rows = connection.execute("""
            SELECT status, COUNT(*) AS count
            FROM scans
            GROUP BY status
        """).fetchall()

        message_warning_rows = connection.execute("""
            SELECT warnings FROM scans WHERE warnings != ''
        """).fetchall()

        url_rows = connection.execute("""
            SELECT status, COUNT(*) AS count
            FROM url_scans
            GROUP BY status
        """).fetchall()

        url_warning_rows = connection.execute("""
            SELECT warnings FROM url_scans WHERE warnings != ''
        """).fetchall()


        url_with_warnings_count = connection.execute("""
            SELECT COUNT(*)
            FROM url_scans
            WHERE warnings IS NOT NULL
            AND warnings != ''
        """).fetchone()[0]


    message_counts = {
        row["status"]: row["count"] for row in message_rows
    }
    url_counts = {
        row["status"]: row["count"] for row in url_rows
    }

    warning_counts = {}

    for row in list(message_warning_rows) + list(url_warning_rows):
        for warning in row["warnings"].split("|||"):
            if warning:
                warning_counts[warning] = warning_counts.get(warning, 0) + 1

    top_warnings = sorted(
        warning_counts.items(),
        key=lambda item: item[1],
        reverse=True,
    )[:8]

    total_message_scans = sum(message_counts.values())
    total_url_scans = sum(url_counts.values())

    return render_template(
        "insights.html",
        active_page="insights",
        total_scans=total_message_scans + total_url_scans,
        message_scans=total_message_scans,
        url_scans=total_url_scans,
        suspicious_count=message_counts.get("Suspicious", 0),
        legitimate_count=message_counts.get("Likely legitimate", 0),
        high_url_risk_count=url_counts.get("High structural risk", 0),
        suspicious_url_count=url_with_warnings_count,
        top_warnings=top_warnings,
    )


@app.route("/scan/<int:scan_id>")
def scan_detail(scan_id):
    with get_db() as connection:
        row = connection.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()

    if row is None:
        return redirect(url_for("history"))

    scan = dict(row)
    scan["warnings"] = (
        scan["warnings"].split("|||") if scan["warnings"] else []
    )

    return render_template(
        "scan_detail.html",
        scan=scan,
        active_page="history",
    )


@app.route("/clear-history", methods=["POST"])
def clear_history():
    with get_db() as connection:
        connection.execute("DELETE FROM scans")

        # Clear URL history only if its table exists.
        table_exists = connection.execute("""
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name = 'url_scans'
        """).fetchone()

        if table_exists:
            connection.execute("DELETE FROM url_scans")

    return redirect(url_for("history"))


@app.errorhandler(404)
def page_not_found(_error):
    return render_template("404.html"), 404


init_db()

if __name__ == "__main__":
    app.run(debug=True)
