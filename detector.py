import re

def detect_attack(user_input):

    patterns = {

        "SQL Injection": [
            r"or\s+1=1",
            r"union\s+select",
            r"drop\s+table",
            r"select\s+\*",
            r"insert\s+into",
            r"delete\s+from",
            r"update\s+.*set",
            r"--",
            r";\s*drop",
            r"information_schema"
        ],

        "XSS": [
            r"<script.*?>",
            r"</script>",
            r"javascript:",
            r"onerror",
            r"onload",
            r"onclick",
            r"alert\s*\(",
            r"document\.cookie",
            r"<iframe",
            r"<img"
        ],

        "Directory Traversal": [
            r"\.\./",
            r"\.\.\\",
            r"/etc/passwd",
            r"/etc/shadow",
            r"windows/system32",
            r"boot\.ini"
        ],

        "Command Injection": [
            r";",
            r"\|\|",
            r"&&",
            r"\|",
            r"whoami",
            r"net\s+user",
            r"ipconfig",
            r"ifconfig",
            r"cat\s+/etc/passwd",
            r"ping\s+"
        ]
    }

    text = user_input.lower().strip()

    for attack_type, rules in patterns.items():

        for rule in rules:

            if re.search(rule, text):

                return attack_type

    return None