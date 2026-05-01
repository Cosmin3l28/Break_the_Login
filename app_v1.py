from flask import Flask, request, jsonify, render_template, make_response
import psycopg2
import jwt
import datetime
import base64

app = Flask(__name__)
# Vulnerabilitate 4.5: Cheie secreta slaba si previzibila
app.config['SECRET_KEY'] = 'secret-foarte-slab-123' 

def get_db_connection():
    conn = psycopg2.connect(
        host="localhost",
        database="authx_db",
        user="postgres",
        password="cosmin"
    )
    return conn

def log_audit(user_id, action, resource, resource_id=None):
    conn = get_db_connection()
    cur = conn.cursor()
    ip_address = request.remote_addr 
    try:
        cur.execute(
            "INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address) VALUES (%s, %s, %s, %s, %s)",
            (user_id, action, resource, resource_id, ip_address)
        )
        conn.commit()
    except Exception as e:
        print(f"Eroare audit: {e}")
    finally:
        cur.close()
        conn.close()

# --- RUTE INTERFATA ---
@app.route('/')
def home(): return render_template('index.html')

@app.route('/register')
def register_page(): return render_template('register.html')

@app.route('/login')
def login_page(): return render_template('login.html')

# --- API ENDPOINTS VULNERABILE ---

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password') # Vulnerabilitate 4.1: Fara validare complexitate

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Vulnerabilitate 4.2: Stocare in clar (fara hashing)
        cur.execute(
            "INSERT INTO users (email, password_hash, role) VALUES (%s, %s, 'USER') RETURNING id",
            (email, password)
        )
        user_id = cur.fetchone()[0]
        conn.commit()
        log_audit(user_id, 'REGISTER_SUCCESS', 'auth')
        return jsonify({"message": "Cont creat cu succes!"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, password_hash, role FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    
    # Vulnerabilitate 4.4: User Enumeration (Mesaj specific daca userul nu exista)
    if not user:
        return jsonify({"error": "Acest email nu exista in sistem."}), 404
    
    user_id, stored_password, role = user
    
    # Vulnerabilitate 4.3: Lipsa Rate Limiting (Pastram verificarea simpla)
    if password != stored_password:
        return jsonify({"error": "Parola gresita."}), 401

    # Vulnerabilitate 4.5: Token JWT cu expirare la 1 an
    token = jwt.encode({
        'user_id': user_id,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=365)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    log_audit(user_id, 'LOGIN_SUCCESS', 'auth')
    
    # Vulnerabilitate 4.5: Setare Cookie fara flag-uri de securitate (HttpOnly=False)
    response = make_response(jsonify({"message": "Login succes!", "token": token}))
    response.set_cookie('session_id', token, httponly=False, secure=False) 
    return response

@app.route('/api/logout', methods=['POST'])
def logout():
    # Vulnerabilitate 3.3 & 4.5: Logout care nu invalideaza nimic in realitate
    return jsonify({"message": "Te-ai delogat (token-ul ramane totusi valid)."}), 200

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    # Vulnerabilitate 4.6: Token predictibil bazat pe Base64
    token = base64.b64encode(email.encode()).decode()
    return jsonify({"message": "Token generat", "token": token}), 200

@app.route('/api/tickets', methods=['GET'])
def get_tickets():
    # Vulnerabilitate IDOR: Returneaza toate tichetele fara a verifica proprietarul
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM tickets")
    tickets = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(tickets)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)