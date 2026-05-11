import jwt

print("=== JWT VERIFIER ===\n")

# =========================
# Input JWT & secret
# =========================
token = input("Enter JWT Token:\n")
secret_key = input("\nEnter SECRET key to verify JWT: ")

# =========================
# Verify & decode
# =========================
try:
    decoded_data = jwt.decode(
        token,
        secret_key,
        algorithms=["HS256"]
    )

    print("\n✅ Signature is VALID!")
    print("Decoded JWT Data:")
    print("-------------------")
    print(f"ID    : {decoded_data['id']}")
    print(f"Name  : {decoded_data['name']}")
    print(f"Email : {decoded_data['email']}")

except jwt.ExpiredSignatureError:
    print("\n❌ Token expired!")

except jwt.InvalidSignatureError:
    print("\n❌ WRONG signature! Verification failed.")

except jwt.InvalidTokenError:
    print("\n❌ Invalid token!")
