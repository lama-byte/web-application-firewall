from flask import Flask, render_template, jsonify
import re, os

app = Flask(__name__)
LOG_FILE = "/sample_logs/waf.log"

def read_logs():
    blocked, allowed, flagged = 0, 0, 0
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            for line in f :
                match = re.search(r"(BLOCKED|ALLOWED|FLAGGED):\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", line)
                if match :
                    status,ip,path,date,time,score = match.groups()
                    logs.append ({"status":status,"ip":ip, "path":path, "date":date, "time":time, "score":score})
                    if status == "BLOCKED":
                        blocked += 1
                    elif status == "ALLOWED":
                        allowed += 1
                    else:
                        flagged += 1
    return blocked, allowed, flagged, logs

@app.route("/")
def home():
    return render_template ("dashboard.html")

@app.route("/data")
def data():
    blocked,allowed,flagged,logs = read_logs()
    return jsonify({"blocked":blocked, "allowed":allowed, "flagged":flagged, "logs":logs})

if __name__ == "__main__":
    app.run(port=9090)
