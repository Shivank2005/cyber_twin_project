from flask import Flask, request, render_template, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import mysql.connector
from ldap3 import Server, Connection, ALL
import bcrypt
import os
from dotenv import load_dotenv

load_dotenv()
from models.AI_agent3.session_hijacking import run_session_model
from models.AI_agent2.XSS_attack_prediction import run_xss_model, check_payload_xss
from models.AI_agent1.sql_injection_detectio import run_sql_model, check_payload_sql

from models.AI_agent1.sql_injection_detectio import run_sql_model
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'default_secret')

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.login_message_category = 'warning'
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, username):
        self.id = username  # Flask-Login requires an 'id' attribute
        self.username = username

# Simple memory cache to prevent massive Database latency on every HTTP request
user_cache = {}

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
    if request.path.startswith('/static') or request.path in ['/logout', '/sql', '/xss', '/session']:
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
                return render_template('waf_blocked.html', reason="SQL Injection Detected"), 403
                
            if check_payload_xss(val):
                username = current_user.username if current_user.is_authenticated else "Anonymous"
                log_threat(username, 'WAF Block: XSS', 'CRITICAL')
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

    threat_count = get_total_threats()
    risk_level, risk_color = get_risk_level(threat_count)

    return render_template('home.html',
                           session_result=session_result,
                           show_session=show_session,
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

        # Save to LDAP
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
                flash("Error binding to LDAP server during registration.", "danger")
                return redirect(url_for('register'))
        except Exception as e:
            flash(f"Error saving to LDAP: {e}", "danger")
            return redirect(url_for('register'))

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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

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
                user = User(username=username)
                login_user(user)
                # Redirect to next url or home
                next_page = request.args.get('next')
                return redirect(next_page or url_for('home'))
            else:
                flash("Invalid password", "danger")
                return redirect(url_for('login'))
        else:
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