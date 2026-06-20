from datetime import datetime

def log_event(ip, payload, result):

    with open("attacks.log", "a") as f:

        timestamp = datetime.now()

        f.write(
            f"{timestamp} | {ip} | {payload} | {result}\n"
        )