from flask import Flask, request, jsonify, render_template_string
from datetime import datetime

app = Flask(__name__)

ATTEMPT = {}
BLOCKED = set()
LEVEL = 1

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

HTML = """
<!DOCTYPE html>
<html>
<head>
<title>Secure Login</title>
<style>
body{font-family:sans-serif;background:#0f0f1a;color:white;text-align:center;margin-top:60px}
input{padding:10px;margin:5px;border-radius:5px;border:none}
button{padding:10px 20px;border:none;border-radius:5px;background:#4e73df;color:white}
</style>
</head>
<body>

<h2>Secure Login System</h2>

<input id="user" placeholder="Username"><br>
<input id="pw" type="password" placeholder="Password"><br>
<button onclick="login()">Login</button>

<script>
function login(){
 fetch('/event',{
  method:'POST',
  headers:{'Content-Type':'application/json'},
  body:JSON.stringify({
    action:'login',
    username:document.getElementById('user').value,
    password:document.getElementById('pw').value
  })
 }).then(r=>r.json()).then(d=>alert(d.status))
}

fetch('/event',{
 method:'POST',
 headers:{'Content-Type':'application/json'},
 body:JSON.stringify({action:'visit'})
});
</script>

</body>
</html>
"""

@app.route("/")
def home():
    return render_template_string(HTML)

@app.route("/event", methods=["POST"])
def event():
    ip = request.remote_addr
    data = request.json
    action = data.get("action")

    if ip in BLOCKED:
        log(f"BLOCKED IP mencoba akses: {ip}")
        return jsonify({"status": "blocked"}), 403

    if action == "visit":
        log(f"VISIT  | {ip} membuka web")

    if action == "login":
        user = data.get("username")
        pw = data.get("password")
        log(f"LOGIN  | {ip} | user:{user} pw:{pw}")

        if LEVEL >= 2 and pw != "admin123":
            ATTEMPT[ip] = ATTEMPT.get(ip, 0) + 1
            log(f"FAIL   | Salah ({ATTEMPT[ip]}x)")

            if ATTEMPT[ip] >= 5 and LEVEL >= 3:
                BLOCKED.add(ip)
                log(f"ALERT  | Brute force! {ip} diblokir")

            return jsonify({"status": "fail"})

        return jsonify({"status": "success"})

    return jsonify({"status": "ok"})

@app.route("/level/<int:lvl>")
def level(lvl):
    global LEVEL
    LEVEL = lvl
    log(f"SECURITY LEVEL -> {LEVEL}")
    return f"Level {LEVEL}"

app.run(host="0.0.0.0", port=5000)
