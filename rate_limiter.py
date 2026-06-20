from datetime import datetime

request_tracker = {}

def check_rate_limit(ip):

    now = datetime.now()

    if ip not in request_tracker:
        request_tracker[ip] = []

    request_tracker[ip].append(now)

    recent = []

    for timestamp in request_tracker[ip]:

        diff = (now - timestamp).seconds

        if diff < 60:
            recent.append(timestamp)

    request_tracker[ip] = recent

    if len(recent) > 5:
        return True

    return False