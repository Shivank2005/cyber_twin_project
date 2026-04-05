from flask import Flask, request, render_template, redirect, url_for
import mysql.connector
from ldap3 import Server, Connection, ALL
import bcrypt
from models.AI_agent3.session_hijacking import run_session_model
from models.AI_agent2.XSS_attack_prediction import run_xss_model
from models.AI_agent1.sql_injection_detectio import run_sql_model

threat_count = 0
app = Flask(__name__)

# Global variables for threat count and risk level


# MySQL Configuration (Database Server)
db_config = {
    # 'host': '10.1.76.119',  # Database Server IP
    # 'user': 'DrStrange',    # Database username
    # 'password': 'DrStrange#02',  # Database user password
    # 'database': 'SecureX'   # Database name
    'host': 'localhost',  # Database Server IP
    'user': 'root',    # Database username
    'password': 'ss17052005',  # Database user password
    'database': 'cyberx'   # Database name
}

# # LDAP Configuration (Authentication Server)
# ldap_server = "ldap://10.1.76.68"  # LDAP Server IP
# ldap_user_dn = "cn=admin,dc=nodomain"  # Admin DN for LDAP
# ldap_password = "AuthAdmin@09"  # LDAP admin password
# ldap_base_dn = "dc=nodomain"  # Base DN for LDAP

# LDAP Configuration (LOCAL DOCKER LDAP)
ldap_server = "ldap://127.0.0.1:389"
ldap_user_dn = "cn=admin,dc=cyberx,dc=local"
ldap_password = "admin"
ldap_base_dn = "dc=cyberx,dc=local"



@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/xss', methods=['GET', 'POST'])
def xss():
    global threat_count

    if request.method == 'POST':
        result = run_xss_model()

        # If model detects attack → increment
        if result['accuracy'] < 1:  # or customize logic
            threat_count += 1

        return render_template('home.html',
                               xss_result=result,
                               show_xss=True,
                               threat_count=threat_count)

    return render_template('home.html', show_xss=False, threat_count=threat_count)

# @app.route('/sql')
# def sql():
#     result = run_sql_model()
#     return render_template('home.html', results=result)

# @app.route('/sql', methods=['GET', 'POST'])
# def sql():
#     global threat_count

#     if request.method == 'POST':
#         results = run_sql_model()

#         # Count detected attacks
#         attacks = sum(1 for r in results if "Detected" in r['Result'])
#         threat_count += attacks

#         risk_level, risk_color = get_risk_level(threat_count)

#     #     return render_template('home.html',
#     #                            results=results,
#     #                            show_table=True,
#     #                            threat_count=threat_count)

#     # return render_template('home.html', show_table=False, threat_count=threat_count)

#     return render_template('home.html',
#                            results=results if request.method=='POST' else None,
#                            show_table=request.method=='POST',
#                            threat_count=threat_count,
#                            risk_level=risk_level,
#                            risk_color=risk_color)

@app.route('/sql', methods=['GET', 'POST'])
def sql():
    global threat_count

    results = None  # ✅ default
    show_table = False  # ✅ default

    if request.method == 'POST':
        results = run_sql_model()
        show_table = True

        # Count detected attacks
        attacks = sum(1 for r in results if "Detected" in r['Result'])
        threat_count += attacks

    # ✅ ALWAYS calculate (important)
    risk_level, risk_color = get_risk_level(threat_count)

    return render_template('home.html',
                           results=results,
                           show_table=show_table,
                           threat_count=threat_count,
                           risk_level=risk_level,
                           risk_color=risk_color)

# @app.route('/session', methods=['GET', 'POST'])
# def session():
#     global threat_count

#     if request.method == 'POST':
#         result = run_session_model()

#         # Example condition
#         if result['accuracy'] < 0.95:
#             threat_count += 1

#         return render_template('home.html',
#                                session_result=result,
#                                show_session=True,
#                                threat_count=threat_count)

#     return render_template('home.html', show_session=False, threat_count=threat_count)
@app.route('/session', methods=['GET', 'POST'])
def session():
    global threat_count

    session_result = None  # ✅ default
    show_session = False   # ✅ default

    if request.method == 'POST':
        session_result = run_session_model()
        show_session = True

        # Count threat (your logic)
        if session_result['accuracy'] < 0.95:
            threat_count += 1

    # ✅ ALWAYS calculate risk
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
            return f"Error saving to database: {e}"

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
                        # 'userPassword': hashed_password.decode('utf-8')  # Store hashed password
                        'userPassword': password
                    }
                )
                conn.unbind()
            else:
                return "Error binding to LDAP server during registration."
        except Exception as e:
            return f"Error saving to LDAP: {e}"

        return redirect('/login')

    return render_template('register.html')



# @app.route('/login', methods=['GET', 'POST'])
# def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # LDAP Authentication
        try:
            server = Server(ldap_server, get_info=ALL)
            conn = Connection(server, user=ldap_user_dn, password=ldap_password)
            if conn.bind():
                user_dn = f"cn={username},{ldap_base_dn}"
                conn.search(search_base=ldap_base_dn, search_filter=f"(cn={username})", attributes=['userPassword'])

                if conn.entries:
                    stored_password = conn.entries[0].userPassword.value
                    # The password from LDAP is already in bytes, so don't use .encode() here
                    if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                        return render_template('home.html')  # Render home.html on successful login
                    else:
                        return "Invalid credentials! <a href='/login'>Try again</a>"
                else:
                    return "User not found in LDAP! <a href='/login'>Try again</a>"
            else:
                return "Error binding to LDAP server during login."
        except Exception as e:
            return f"Error: {e}"

    return render_template('login.html')


def get_risk_level(threat_count):
    if threat_count < 3:
        return "LOW", "lightgreen"
    elif threat_count < 6:
        return "MEDIUM", "orange"
    else:
        return "HIGH", "red"

@app.route('/login', methods=['GET', 'POST'])
def login():
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
                return render_template('home.html')
            else:
                return "Invalid password"
        else:
            return "User not found"

    return render_template('login.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)