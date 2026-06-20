from flask import Flask, request, render_template
from detector import detect_attack
from logger import log_event
from rate_limiter import check_rate_limit
app = Flask(__name__)

@app.route("/")
def home():

    payload = request.args.get("payload", "")
    result_message = ""

    if payload:

        result = detect_attack(payload)

        ip = request.remote_addr

        if check_rate_limit(ip):

            log_event(
                ip,
                payload,
                "Rate Limit Exceeded"
            )

            result_message = "Suspicious Activity Detected - Rate Limit Exceeded"

            return render_template(
                "index.html",
                result=result_message
            )
        elif result:
            log_event(ip, payload, result)
            result_message = f"🚨 Attack Detected: {result}"

        else:
            log_event(ip, payload, "Allowed")
            result_message = "✅ Request Allowed"

    return render_template(
        "index.html",
        result=result_message
    )

@app.route("/dashboard")
def dashboard():

    with open("attacks.log", "r") as f:
        logs = f.readlines()

    sql = 0
    xss = 0
    traversal = 0
    command = 0
    allowed = 0
    rate_limit = 0

    for line in logs:

        if "SQL Injection" in line:
            sql += 1

        elif "XSS" in line:
            xss += 1

        elif "Directory Traversal" in line:
            traversal += 1

        elif "Command Injection" in line:
            command += 1

        elif "Allowed" in line:
            allowed += 1

        elif "Rate Limit Exceeded" in line:
            rate_limit += 1

    total = len(logs)

    return render_template(
        "dashboard.html",
        total=total,
        allowed=allowed,
        sql=sql,
        xss=xss,
        traversal=traversal,
        command=command,
        rate_limit=rate_limit,
        logs="".join(logs)
    )