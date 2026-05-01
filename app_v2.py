from flask import Flask, request, jsonify, render_template, make_response
import psycopg2
import jwt
import datetime
import secrets
import base64
import re
import bcrypt

app = Flask(__name__)

# FIX 4.5: Cheie secreta puternica, random la fiecare pornire
app.config['SECRET_KEY'] = secrets.token_hex(32)

# FIX 4.5: Blacklist token-uri invalidate la logout
token_blacklist = set()

# FIX 4.6: Reset tokens in memorie
reset_tokens = {}

# ==========================================
# CONFIGURARE BAZA DE DATE
# ==========================================
def get_db_connection():
    conn = psycopg2.connect(
        host="localhost",
        database="authx_db",
        user="postgres",
        password="cosmin"
    )
    return conn

# ==========================================
# FUNCTIE DE AUDIT LOGGING
# ==========================================
def log_audit(user_id, action, resource, resource_id=None):
    conn = get_db_connection()
    cur = conn.cursor()
    ip_address = request.remote_addr
    try:
        cur.execute(
            """
            INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address) 
            VALUES (%s, %s, %s, %s, %s)
            """,
            (user_id, action, resource, resource_id, ip_address)
        )
        conn.commit()
    except Exception as e:
        print(f"Eroare audit: {e}")
    finally:
        cur.close()
        conn.close()

# ==========================================
# DECORATOR VERIFICARE JWT
# ==========================================
from functools import wraps

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
        if not token:
            token = request.cookies.get('session_id')
        if not token:
            return jsonify({"error": "Autentificare necesara."}), 401
        # FIX 4.5: Verificare blacklist
        if token in token_blacklist:
            return jsonify({"error": "Token invalidat. Logheaza-te din nou."}), 401
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            request.current_user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Sesiunea a expirat."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token invalid."}), 401
        return f(*args, **kwargs)
    return decorated

# ==========================================
# RUTE PENTRU INTERFATA WEB
# ==========================================
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/dashboard')
def dashboard_page():
    return render_template('dashboard.html')

@app.route('/forgot-password')
def forgot_password_page():
    return render_template('forgot_password.html')

@app.route('/reset-password')
def reset_password_page():
    return render_template('reset_password.html')

# ==========================================
# API: INREGISTRARE
# ==========================================
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    # FIX 4.1: Password Policy
    if not password or len(password) < 8:
        return jsonify({"error": "Parola trebuie sa aiba minim 8 caractere!"}), 400

    if not re.search(r"[A-Z]", password) or \
       not re.search(r"[a-z]", password) or \
       not re.search(r"[0-9]", password) or \
       not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return jsonify({"error": "Parola trebuie sa contina cel putin o majuscula, o minuscula, o cifra si un simbol special!"}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # FIX 4.2: Hash bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        cur.execute(
            "INSERT INTO users (email, password_hash) VALUES (%s, %s) RETURNING id",
            (email, hashed_password)
        )

        user_id = cur.fetchone()[0]
        conn.commit()

        log_audit(user_id, 'REGISTER_SUCCESS', 'auth')
        return jsonify({"message": "Cont creat si securizat cu succes!"}), 201

    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"error": "Email-ul exista deja in sistem!"}), 400
    except Exception as e:
        conn.rollback()
        return jsonify({"error": "Eroare la inregistrare."}), 500
    finally:
        cur.close()
        conn.close()

# ==========================================
# API: LOGIN
# ==========================================
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT id, password_hash, role, locked FROM users WHERE email = %s", (email,))
    user = cur.fetchone()

    # FIX 4.4: Mesaj generic
    if not user:
        cur.close()
        conn.close()
        log_audit(None, 'LOGIN_FAILED_GENERIC', 'auth')
        return jsonify({"error": "Email sau parola incorecta."}), 401

    user_id, stored_password_hash, role, is_locked = user

    # FIX 4.3: Cont blocat
    if is_locked:
        cur.close()
        conn.close()
        return jsonify({"error": "Contul tau este blocat din cauza prea multor incercari esuate. Reseteaza parola pentru deblocare."}), 403

    # FIX 4.2: Verificare bcrypt
    if not bcrypt.checkpw(password.encode('utf-8'), stored_password_hash.encode('utf-8')):
        log_audit(user_id, 'LOGIN_FAILED_GENERIC', 'auth')

        # FIX 4.3: Numara greselile din audit_logs si blocheaza contul
        cur.execute("""
            SELECT COUNT(*) FROM audit_logs 
            WHERE user_id = %s 
            AND action = 'LOGIN_FAILED_GENERIC' 
            AND timestamp > NOW() - INTERVAL '15 minutes'
        """, (user_id,))
        failed_attempts = cur.fetchone()[0]

        if failed_attempts >= 5:
            cur.execute("UPDATE users SET locked = TRUE WHERE id = %s", (user_id,))
            conn.commit()
            log_audit(user_id, 'ACCOUNT_LOCKED', 'auth')
            cur.close()
            conn.close()
            return jsonify({"error": "Prea multe incercari esuate. Contul tau a fost blocat!"}), 429

        cur.close()
        conn.close()
        return jsonify({"error": "Email sau parola incorecta."}), 401

    # FIX 4.5: Token JWT 15 minute
    token = jwt.encode({
        'user_id': user_id,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    log_audit(user_id, 'LOGIN_SUCCESS', 'auth')
    cur.close()
    conn.close()

    # FIX 4.5: Cookie cu flag-uri de securitate
    response = make_response(jsonify({"message": "Autentificare reusita!"}))
    response.set_cookie(
        'session_id', token,
        httponly=True,      # nu accesibil din JavaScript
        secure=True,        # doar HTTPS
        samesite='Strict',  # protectie CSRF
        max_age=900         # 15 minute
    )
    return response

# ==========================================
# API: LOGOUT
# ==========================================
@app.route('/api/logout', methods=['POST'])
@require_auth
def logout():
    # FIX 4.5: Invalidam token-ul in blacklist
    auth_header = request.headers.get('Authorization', '')
    token = auth_header[7:] if auth_header.startswith('Bearer ') else request.cookies.get('session_id')
    if token:
        token_blacklist.add(token)

    log_audit(request.current_user.get('user_id'), 'LOGOUT', 'auth')

    response = make_response(jsonify({"message": "Delogat cu succes."}))
    response.delete_cookie('session_id')
    return response

# ==========================================
# API: TICKETS (FIX IDOR)
# ==========================================
@app.route('/api/tickets', methods=['GET'])
@require_auth
def get_tickets():
    current_user_id = request.current_user['user_id']
    current_role = request.current_user.get('role', 'USER')

    conn = get_db_connection()
    cur = conn.cursor()

    if current_role == 'MANAGER':
        # Managerii vad toate tichetele
        cur.execute("SELECT id, title, description, status FROM tickets")
    else:
        # FIX IDOR: Userii vad DOAR tichetele lor
        cur.execute(
            "SELECT id, title, description, status FROM tickets WHERE owner_id = %s",
            (current_user_id,)
        )

    tickets = cur.fetchall()
    cur.close()
    conn.close()

    ticket_list = []
    for t in tickets:
        ticket_list.append({"id": t[0], "title": t[1], "description": t[2], "status": t[3]})

    return jsonify(ticket_list)

# ==========================================
# API: FORGOT PASSWORD (MODIFICAT PENTRU TESTARE)
# ==========================================
@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    # Pregatim raspunsul generic de succes, indiferent daca userul exista sau nu
    response_data = {
        "message": "Daca adresa de email exista in sistem, vei primi un link."
    }

    # FIX 4.6 + 4.4: Token JWT securizat, mesaj generic
    if user:
        reset_token = jwt.encode({
            'reset_email': email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
        }, app.config['SECRET_KEY'], algorithm="HS256")

        log_audit(user[0], 'FORGOT_PASSWORD_REQUEST', 'auth', email)

        # In productie: trimite tokenul prin email, nu in raspuns
        print(f"[DEV] Reset token pentru {email}: {reset_token}")
        
        # PENTRU DEZVOLTARE/TESTARE: Trimitem tokenul catre frontend
        response_data["token"] = reset_token

    return jsonify(response_data), 200

# ==========================================
# API: RESET PASSWORD
# ==========================================
@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')

    # FIX 4.1: Politica de parole la resetare
    if not new_password or len(new_password) < 8 or \
       not re.search(r"[A-Z]", new_password) or \
       not re.search(r"[a-z]", new_password) or \
       not re.search(r"[0-9]", new_password) or \
       not re.search(r"[!@#$%^&*(),.?\":{}|<>]", new_password):
        return jsonify({"error": "Parola noua trebuie sa aiba minim 8 caractere, o majuscula, o cifra si un simbol special!"}), 400

    try:
        # FIX 4.6: Verificare JWT (expirare + semnatura)
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        email = decoded_token['reset_email']
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Link-ul de resetare a expirat (15 minute)!"}), 400
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token de resetare invalid!"}), 400

    # FIX 4.2: Hash noua parola
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = get_db_connection()
    cur = conn.cursor()

    # FIX 4.3: La resetare deblocam si contul
    cur.execute(
        "UPDATE users SET password_hash = %s, locked = FALSE WHERE email = %s",
        (hashed_password, email)
    )
    conn.commit()

    cur.execute("SELECT id FROM users WHERE email = %s", (email,))
    user_id = cur.fetchone()[0]

    log_audit(user_id, 'PASSWORD_RESET_SUCCESS_AND_UNLOCKED', 'auth', email)
    cur.close()
    conn.close()

    return jsonify({"message": "Parola a fost resetata, iar contul a fost deblocat cu succes!"}), 200

if __name__ == '__main__':
    app.run(debug=True)