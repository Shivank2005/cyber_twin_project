from flask import Flask, request, render_template, redirect, url_for
import mysql.connector
from ldap3 import Server, Connection, ALL
import bcrypt

app = Flask(__name__)

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



@app.route('/login', methods=['GET', 'POST'])
def login():
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




if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)