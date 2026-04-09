from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import json
import os

app = Flask(__name__)
app.secret_key = "secret123"

# Ensure users.json exists
if not os.path.exists("users.json"):
    with open("users.json", "w") as f:
        json.dump({}, f)

def load_users():
    with open("users.json", "r") as f:
        return json.load(f)

def save_users(users):
    with open("users.json", "w") as f:
        json.dump(users, f, indent=4)

# LOGIN
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get("username")
        pwd = request.form.get("password")

        users = load_users()

        if user in users and users[user] == pwd:
            session['user'] = user
            return redirect(url_for('ui'))
        else:
            return render_template("login.html", error="Invalid Credentials ❌")

    return render_template("login.html")

# REGISTER
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = request.form.get("username")
        pwd = request.form.get("password")

        users = load_users()

        if user in users:
            return render_template("register.html", error="User already exists ❌")

        users[user] = pwd
        save_users(users)

        return redirect(url_for('login'))

    return render_template("register.html")

# PROTECTED UI
@app.route('/ui')
def ui():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template("index.html")

# LOGOUT
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

# ANALYZE + FIXED HISTORY
@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    code = data.get("code", "").lower()

    threats = []

    if "select" in code:
        threats.append("SQL Injection (High Risk)")

    if "password" in code:
        threats.append("Weak Authentication (Medium Risk)")

    if "<script>" in code:
        threats.append("XSS Attack (High Risk)")

    if "upload" in code:
        threats.append("Insecure File Upload (Medium Risk)")

    if not threats:
        result = "✅ No major threats detected."
    else:
        result = "🚨 Detected Threats:\n\n"
        for i, t in enumerate(threats, 1):
            result += f"{i}. {t}\n"

    # ✅ FIXED USER-SPECIFIC HISTORY
    if "history" not in session or not isinstance(session["history"], dict):
        session["history"] = {}

    user = session.get("user")

    if user not in session["history"]:
        session["history"][user] = []

    session["history"][user].append({
        "input": code,
        "result": result
    })

    return jsonify({"analysis": result})

# FETCH USER HISTORY
@app.route('/history')
def history():
    user = session.get("user")
    if not user:
        return jsonify([])

    return jsonify(session.get("history", {}).get(user, []))


if __name__ == '__main__':
    app.run(debug=True)