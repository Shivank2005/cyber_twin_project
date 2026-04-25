from flask import Flask, request, render_template, redirect, url_for, flash, jsonify, Response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import mysql.connector
from ldap3 import Server, Connection, ALL
import bcrypt
import os
import io
import csv
import time
import smtplib
from email.mime.text import MIMEText
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()
from models.AI_agent3.session_hijacking import run_session_model
from models.AI_agent2.XSS_attack_prediction import run_xss_model, check_payload_xss
from models.AI_agent1.sql_injection_detectio import run_sql_model, check_payload_sql

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'default_secret')

# ========== SESSION TIMEOUT: Auto-logout after 15 minutes of inactivity ==========
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)

# ========== ADMIN USERS: Comma-separated list of admin usernames ==========
ADMIN_USERS = os.getenv('ADMIN_USERS', 'admin').split(',')

# ========== EMAIL ALERT CONFIG ==========
SMTP_SERVER = os.getenv('SMTP_SERVER', '')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USER = os.getenv('SMTP_USER', '')
SMTP_PASS = os.getenv('SMTP_PASS', '')
ALERT_EMAIL = os.getenv('ALERT_EMAIL', '')

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.login_message_category = 'warning'
login_manager.init_app(app)

@app.context_processor
def inject_admin_status():
    """Automatically inject is_admin into all templates"""
    if current_user.is_authenticated:
        return {'is_admin': current_user.username in ADMIN_USERS}
    return {'is_admin': False}

class User(UserMixin):
    def __init__(self, username):
        self.id = username  # Flask-Login requires an 'id' attribute
        self.username = username

# Simple memory cache to prevent massive Database latency on every HTTP request
user_cache = {}

# Brute force protection: track failed login attempts {ip: [timestamps]}
login_attempts = {}

@login_manager.user_loader
def load_user(user_id):
    if user_id in user_cache:
        return user_cache[user_id]
        
    try:
        db = mysql.connector.connect(**db_config)
        cursor = db.cursor()
        cursor.execute("SELECT username FROM users WHERE username=%s", (user_id,))
        result = cursor.fetchone()
        db.close()
        if result:
            user = User(username=result[0])
            user_cache[user_id] = user
            return user
    except Exception as e:
        print(f"Database error during load_user: {e}")
    return None

# Database helper functions for Persistent Analytics
def init_db():
    try:
        db = mysql.connector.connect(**db_config)
        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255),
                threat_type VARCHAR(50),
                severity VARCHAR(20),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.commit()
        db.close()
    except Exception as e:
        print(f"Error initializing DB: {e}")

def get_total_threats():
    try:
        db = mysql.connector.connect(**db_config)
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM threat_logs")
        result = cursor.fetchone()
        db.close()
        return result[0] if result else 0
    except:
        return 0

def log_threat(username, threat_type, severity):
    try:
        db = mysql.connector.connect(**db_config)
        cursor = db.cursor()
        cursor.execute("INSERT INTO threat_logs (username, threat_type, severity) VALUES (%s, %s, %s)",
                       (username, threat_type, severity))
        db.commit()
        db.close()
    except Exception as e:
        print(f"Error logging threat: {e}")

def get_all_threats():
    """Fetch all threat logs for audit page"""
    try:
        db = mysql.connector.connect(**db_config)
        cursor = db.cursor()
        cursor.execute("SELECT id, username, threat_type, severity, timestamp FROM threat_logs ORDER BY timestamp DESC LIMIT 100")
        results = cursor.fetchall()
        db.close()
        return results
    except:
        return []

def get_threat_stats():
    """Fetch threat counts grouped by type for Chart.js"""
    try:
        db = mysql.connector.connect(**db_config)
        cursor = db.cursor()
        cursor.execute("SELECT threat_type, COUNT(*) FROM threat_logs GROUP BY threat_type")
        results = cursor.fetchall()
        db.close()
        return {row[0]: row[1] for row in results}
    except:
        return {}

def get_all_users():
    """Fetch all registered users for admin panel"""
    try:
        db = mysql.connector.connect(**db_config)
        cursor = db.cursor()
        cursor.execute("SELECT username, email FROM users")
        results = cursor.fetchall()
        db.close()
        return results
    except:
        return []

def is_rate_limited(ip):
    """Check if an IP has exceeded 5 failed logins in 60 seconds"""
    now = time.time()
    if ip not in login_attempts:
        return False
    # Clean old attempts (older than 60s)
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < 60]
    return len(login_attempts[ip]) >= 5

def record_failed_login(ip):
    """Record a failed login attempt for brute force tracking"""
    if ip not in login_attempts:
        login_attempts[ip] = []
    login_attempts[ip].append(time.time())

def send_threat_alert(threat_type, severity, username):
    """Send email alert when CRITICAL threats are detected"""
    if not SMTP_SERVER or not ALERT_EMAIL:
        return  # Email not configured, skip silently
    try:
        subject = f"[SecureX ALERT] {severity} Threat Detected: {threat_type}"
        body = f"""SecureX Autonomous WAF Alert
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Threat Type: {threat_type}
Severity: {severity}
Triggered By: {username}
Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
This is an automated alert from SecureX Digital Twin."""
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = SMTP_USER
        msg['To'] = ALERT_EMAIL
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
    except Exception as e:
        print(f"Email alert failed: {e}")

# MySQL Configuration (Database Server)
db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),  # Database Server IP
    'user': os.getenv('DB_USER', 'root'),    # Database username
    'password': os.getenv('DB_PASSWORD', 'ss17052005'),  # Database user password
    'database': os.getenv('DB_NAME', 'cyberx')   # Database name
}



# LDAP Configuration (LOCAL DOCKER LDAP)
ldap_server = os.getenv('LDAP_SERVER', "ldap://127.0.0.1:389")
ldap_user_dn = os.getenv('LDAP_USER_DN', "cn=admin,dc=cyberx,dc=local")
ldap_password = os.getenv('LDAP_PASSWORD', "admin")
ldap_base_dn = os.getenv('LDAP_BASE_DN', "dc=cyberx,dc=local")

# Create Analytics db if missing
init_db()



@app.before_request
def waf_middleware():
    """ Active Digital Twin WAF - Intercepts all traffic payload strings """
    if request.path.startswith('/static') or request.path in ['/logout', '/sql', '/xss', '/session', '/threats', '/admin', '/export', '/scan'] or request.path.startswith('/api/'):
        return

    inputs_to_check = []
    if request.args:
        inputs_to_check.extend(request.args.values())
    # Form data scanning
    if request.form:
        inputs_to_check.extend(request.form.values())

    for val in inputs_to_check:
        if isinstance(val, str):
            if check_payload_sql(val):
                username = current_user.username if current_user.is_authenticated else "Anonymous"
                log_threat(username, 'WAF Block: SQLi', 'CRITICAL')
                send_threat_alert('WAF Block: SQLi', 'CRITICAL', username)
                return render_template('waf_blocked.html', reason="SQL Injection Detected"), 403
                
            if check_payload_xss(val):
                username = current_user.username if current_user.is_authenticated else "Anonymous"
                log_threat(username, 'WAF Block: XSS', 'CRITICAL')
                send_threat_alert('WAF Block: XSS', 'CRITICAL', username)
                return render_template('waf_blocked.html', reason="Cross-Site Scripting Detected"), 403


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return render_template('index.html')

@app.route('/home')
@login_required
def home():
    threat_count = get_total_threats()
    risk_level, risk_color = get_risk_level(threat_count)
    return render_template('home.html', 
                           current_user=current_user, 
                           threat_count=threat_count,
                           risk_level=risk_level,
                           risk_color=risk_color)

@app.route('/xss', methods=['GET', 'POST'])
@login_required
def xss():
    if request.method == 'POST':
        result = run_xss_model()

        # If model detects attack → log it
        if result['accuracy'] < 1:  
            log_threat(current_user.username, 'XSS Payload', 'HIGH')
            send_threat_alert('XSS Payload', 'HIGH', current_user.username)

        threat_count = get_total_threats()
        risk_level, risk_color = get_risk_level(threat_count)
        
        return render_template('home.html',
                               xss_result=result,
                               show_xss=True,
                               threat_count=threat_count,
                               risk_level=risk_level,
                               risk_color=risk_color)

    threat_count = get_total_threats()
    risk_level, risk_color = get_risk_level(threat_count)
    return render_template('home.html', 
                           show_xss=False, 
                           threat_count=threat_count,
                           risk_level=risk_level,
                           risk_color=risk_color)



@app.route('/sql', methods=['GET', 'POST'])
@login_required
def sql():
    results = None
    show_table = False

    if request.method == 'POST':
        results = run_sql_model()
        show_table = True

        attacks = sum(1 for r in results if "Detected" in r['Result'])
        for _ in range(attacks):
            log_threat(current_user.username, 'SQL Injection', 'CRITICAL')
            send_threat_alert('SQL Injection', 'CRITICAL', current_user.username)

    threat_count = get_total_threats()
    risk_level, risk_color = get_risk_level(threat_count)

    return render_template('home.html',
                           results=results,
                           show_table=show_table,
                           threat_count=threat_count,
                           risk_level=risk_level,
                           risk_color=risk_color)




@app.route('/session', methods=['GET', 'POST'])
@login_required
def session():
    session_result = None 
    show_session = False  

    if request.method == 'POST':
        session_result = run_session_model()
        show_session = True

        if session_result['accuracy'] < 0.95:
            log_threat(current_user.username, 'Session Hijacking', 'HIGH')
            send_threat_alert('Session Hijacking', 'HIGH', current_user.username)

    threat_count = get_total_threats()
    risk_level, risk_color = get_risk_level(threat_count)

    return render_template('home.html',
                           session_result=session_result,
                           show_session=show_session,
                           threat_count=threat_count,
                           risk_level=risk_level,
                           risk_color=risk_color)

# ========== FEATURE 1: Threat Audit Log ==========
@app.route('/threats')
@login_required
def threats():
    threat_list = get_all_threats()
    threat_count = get_total_threats()
    stats = get_threat_stats()
    return render_template('threats.html',
                           threats=threat_list,
                           threat_count=threat_count,
                           stats=stats)

# ========== FEATURE 2: REST API Scanner ==========
@app.route('/api/v1/scan', methods=['POST'])
def api_scan():
    """REST API endpoint for external payload scanning"""
    data = request.get_json(force=True, silent=True)
    if not data or 'payload' not in data:
        return jsonify({"error": "Missing 'payload' field"}), 400

    payload = data['payload']
    result = {"payload": payload, "threats": []}

    if check_payload_sql(payload):
        result["threats"].append({"type": "SQL Injection", "severity": "CRITICAL"})
        log_threat("API", "API Scan: SQLi", "CRITICAL")
        send_threat_alert('API Scan: SQLi', 'CRITICAL', 'API')

    if check_payload_xss(payload):
        result["threats"].append({"type": "Cross-Site Scripting", "severity": "CRITICAL"})
        log_threat("API", "API Scan: XSS", "CRITICAL")
        send_threat_alert('API Scan: XSS', 'CRITICAL', 'API')

    if not result["threats"]:
        result["status"] = "CLEAN"
    else:
        result["status"] = "THREAT_DETECTED"

    return jsonify(result)

# ========== FEATURE 4: CSV Report Export ==========
@app.route('/export')
@login_required
def export_csv():
    """Download all threat logs as a CSV file"""
    threats = get_all_threats()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Username', 'Threat Type', 'Severity', 'Timestamp'])
    for t in threats:
        writer.writerow(t)
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=securex_threat_report.csv'}
    )

# ========== FEATURE 7: Admin Panel (Role-Protected) ==========
@app.route('/admin')
@login_required
def admin():
    # Only admin users can access this page
    if current_user.username not in ADMIN_USERS:
        flash("Access denied. Admin privileges required.", "danger")
        return redirect(url_for('home'))
    users = get_all_users()
    threat_list = get_all_threats()
    threat_count = get_total_threats()
    stats = get_threat_stats()
    return render_template('admin.html',
                           users=users,
                           threats=threat_list,
                           threat_count=threat_count,
                           stats=stats)

# ========== FEATURE: Custom Payload Tester ==========
@app.route('/scan', methods=['POST'])
@login_required
def scan_payload():
    payload = request.form.get('payload', '')
    results = []
    if check_payload_sql(payload):
        results.append({'type': 'SQL Injection', 'severity': 'CRITICAL', 'color': '#ff4444'})
        log_threat(current_user.username, 'Manual Scan: SQLi', 'CRITICAL')
        send_threat_alert('Manual Scan: SQLi', 'CRITICAL', current_user.username)
    if check_payload_xss(payload):
        results.append({'type': 'Cross-Site Scripting', 'severity': 'CRITICAL', 'color': '#ffaa00'})
        log_threat(current_user.username, 'Manual Scan: XSS', 'CRITICAL')
        send_threat_alert('Manual Scan: XSS', 'CRITICAL', current_user.username)
    if not results:
        results.append({'type': 'No Threats Found', 'severity': 'CLEAN', 'color': '#00ffcc'})

    threat_count = get_total_threats()
    risk_level, risk_color = get_risk_level(threat_count)
    return render_template('home.html',
                           scan_payload=payload,
                           scan_results=results,
                           show_scan=True,
                           threat_count=threat_count,
                           risk_level=risk_level,
                           risk_color=risk_color)

@app.route('/register', methods=['GET', 'POST'])
def register():



    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Save to MySQL Database
        try:
            db = mysql.connector.connect(**db_config)
            cursor = db.cursor()
            cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                           (username, email, hashed_password))
            db.commit()
            db.close()
        except Exception as e:
            flash(f"Error saving to database: {e}", "danger")
            return redirect(url_for('register'))

        # Save to LDAP (Optional / Soft-Fail)
        try:
            server = Server(ldap_server, get_info=ALL)
            conn = Connection(server, user=ldap_user_dn, password=ldap_password)
            if conn.bind():
                user_dn = f"cn={username},{ldap_base_dn}"
                conn.add(
                    dn=user_dn,
                    object_class=['inetOrgPerson'],
                    attributes={
                        'cn': username,
                        'sn': username,
                        'mail': email,
                        'userPassword': hashed_password.decode('utf-8')  # Store hashed password securely
                    }
                )
                conn.unbind()
            else:
                print("Warning: Could not bind to LDAP server during registration (Feature Disabled)")
        except Exception as e:
            print(f"Warning: LDAP synchronization skipped: {e}")

        flash("Registration successful! Please login.", "success")
        return redirect('/login')

    return render_template('register.html')





def get_risk_level(threat_count):
    if threat_count < 3:
        return "LOW", "lightgreen"
    elif threat_count < 6:
        return "MEDIUM", "orange"
    else:
        return "HIGH", "red"

# ========== FEATURE 5: Brute Force Protected Login ==========
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        client_ip = request.remote_addr
        username = request.form['username']
        password = request.form['password']

        # Check brute force rate limit
        if is_rate_limited(client_ip):
            log_threat(username, 'Brute Force Blocked', 'CRITICAL')
            send_threat_alert('Brute Force Blocked', 'CRITICAL', username)
            flash("Too many failed attempts. Please wait 60 seconds.", "danger")
            return redirect(url_for('login'))

        db = mysql.connector.connect(**db_config)
        cursor = db.cursor()
        cursor.execute("SELECT password FROM users WHERE username=%s", (username,))
        result = cursor.fetchone()
        db.close()

        if result:
            stored_password = result[0]

            if isinstance(stored_password, str):
                stored_password = stored_password.encode('utf-8')

            if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                # Clear failed attempts on success
                login_attempts.pop(client_ip, None)
                user = User(username=username)
                login_user(user, remember=True)
                # Make session permanent for timeout tracking
                from flask import session as flask_session
                flask_session.permanent = True
                next_page = request.args.get('next')
                return redirect(next_page or url_for('home'))
            else:
                record_failed_login(client_ip)
                flash("Invalid password", "danger")
                return redirect(url_for('login'))
        else:
            record_failed_login(client_ip)
            flash("User not found", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been successfully logged out.", "success")
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)