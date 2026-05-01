#!/usr/bin/env python3
"""
4.1 - Weak Password Policy
Demonstreaza ca aplicatia accepta parole extrem de slabe
"""

import requests
import json

BASE_URL = "http://localhost:5000"

weak_passwords = [
    "1",
    "12",
    "123",
    "abc",
    "password",
    "a",
    " ",
    "111111",
]

print("=" * 60)
print("PoC 4.1 - Weak Password Policy")
print("Incerc sa creez conturi cu parole slabe...")
print("=" * 60)

for pwd in weak_passwords:
    email = f"test_{len(pwd)}_{pwd[:3].strip()}@test.com"
    payload = {"email": email, "password": pwd}

    try:
        r = requests.post(f"{BASE_URL}/api/register", json=payload, timeout=5)
        status = r.status_code
        body = r.json()

        if status == 201:
            print(f"[VULNERABIL]  Parola '{pwd}' (lungime={len(pwd)}) -> ACCEPTATA! ({email})")
        else:
            print(f"[OK]          Parola '{pwd}' -> Respinsa: {body.get('error', body)}")
    except Exception as e:
        print(f"[EROARE]      {e}")

print()
print("Concluzie: Orice parola fara validare ->  brute force trivial.")
