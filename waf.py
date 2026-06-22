from flask import Flask, request, Response
from datetime import datetime
import requests, re
import logging

app = Flask(__name__)

BACKEND_URL = "http://192.168.56.107"

# loading attack signatures from rules.txt file 
with open("rules.txt", "r") as f:
    RULES = [line.strip() for line in f if line.strip()]

# Advanced Feature 1 (Scoring)
SCORED_PATTERNS = [
    {"name": "xss_script",      "pattern": r"<script",          "score": 3},
    {"name": "xss_on_event",    "pattern": r"on\w+\s*=",        "score": 2},  # onerror=, onclick=...
    {"name": "sql_boolean",     "pattern": r"\bor\b\s+1=1",     "score": 3},
    {"name": "sql_comment",     "pattern": r"--|/\*",           "score": 2},
    {"name": "path_traversal",  "pattern": r"\.\./",            "score": 2},
    {"name": "cmd_keyword",     "pattern": r"\b(wget|curl)\b",  "score": 2},
    {"name": "php_wrapper",     "pattern": r"php://",           "score": 2},
]

def compute_score(payload: str):
    if not payload:
        return 0, []

    total = 0
    hits = []
    for rule in SCORED_PATTERNS:
        if re.search(rule["pattern"], payload, re.IGNORECASE):
            total += rule["score"]
            hits.append(rule["name"])
    return total, hits

# Advanced Feature 2 (Honeypot)
HONEYPOT_KEYS = {"honeypot", "trap", "debug_token"}
HONEYPOT_HEADER = "X-Honey-Token"

def check_honeypot(req):
    triggers = []
    for key in req.args.keys():
        if key in HONEYPOT_KEYS:
            triggers.append(f"query:{key}")
    for key in req.form.keys():
        if key in HONEYPOT_KEYS:
            triggers.append(f"form:{key}")
    if HONEYPOT_HEADER in req.headers:
        triggers.append(f"header:{HONEYPOT_HEADER}")

    return triggers


def is_malicious(payload):
    for rule in RULES:
        if re.search(rule, payload, re.IGNORECASE):
            return True
    return False


@app.route('/', defaults={'path': ''}, methods=["GET", "POST"])
@app.route('/<path:path>', methods=["GET", "POST"])
def proxy(path):
    data = request.get_data(as_text=True)
    #for logging timestamp
    time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # SCORE-BASED ADVANCED DETECTION
    total_score = 0
    score_hits = []

    s_body, hits_body = compute_score(data)
    total_score += s_body
    score_hits.extend(hits_body)

    for v in request.args.values():
        s_arg, hits_arg = compute_score(v)
        total_score += s_arg
        score_hits.extend(hits_arg)

    SCORE_THRESHOLD = 10

    # HONEYPOT-BASED DETECTION
    hp_triggers = check_honeypot(request)



    #logging certainly malicious requests
    if is_malicious(data) or any(is_malicious(v) for v in request.args.values()) or total_score == SCORE_THRESHOLD:
       with open("/sample_logs/waf.log", "a", encoding="utf-8") as f:
           f.write(f"BLOCKED: {request.remote_addr} {path} {time}  10 {data[:300]}\n")
       return Response("Request blocked by WAF", status=403)

    #logging score-based blocked requests
    elif total_score < SCORE_THRESHOLD and total_score >= 2:
       with open("/sample_logs/waf.log", "a", encoding="utf-8") as f:
           f.write(f"FLAGGED: {request.remote_addr} {path} {time}  {total_score} {data[:300]}\n")
       return Response("\033[93mRequest blocked by WAF (score-based)\033[0m\n", status=403)

    #logging honeypot triggered requests
    elif hp_triggers:
        with open("/sample_logs/waf.log", "a", encoding="utf-8") as f:
            f.write(
                f"BLOCKED: {request.remote_addr} {path} {time}  10 {data[:300]}\n"
            )
        return Response("Request blocked by WAF (honeypot triggered)", status=403)
    #logging allowed requests
    else:
       with open ("/sample_logs/waf.log" , "a") as f:
           f.write(f"ALLOWED: {request.remote_addr} {path} {time}  {total_score} {data[:300]}\n")


    target = f"{BACKEND_URL}/{path}"
    resp = requests.request(
        method=request.method,
        url=target,
        headers={k: v for k, v in request.headers if k.lower() != 'host'},
        data=data,
        allow_redirects=False
    )
    response_header = {(k,v) for k, v in resp.headers.items() if k.lower() != 'content-encoding'}
    return Response(resp.content, resp.status_code, response_header)

if __name__ == "__main__":
    app.run(host='0.0.0.0',port=8080)

