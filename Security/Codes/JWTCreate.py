import jwt
import datetime

print("=== JWT GENERATOR ===\n")

# =========================
# Input user data
# =========================
name = input("Enter your name: ")
email = input("Enter your email: ")
user_id = input("Enter your ID: ")

# =========================
# Input secret key
# =========================
secret_key = input("\nEnter SECRET key to sign JWT: ")

# =========================
# Create payload
# =========================
payload = {
    "id": user_id,
    "name": name,
    "email": email,
    "iat": datetime.datetime.utcnow(),
    "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
}

# =========================
# Generate JWT
# =========================
token = jwt.encode(payload, secret_key, algorithm="HS256")

print("\n✅ JWT Generated Successfully!\n")
print("JWT Token:\n")
print(token)
