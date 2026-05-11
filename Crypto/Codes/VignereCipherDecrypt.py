"""
VignereCipherDecrypt.py
Decryption for Vigenère Cipher.
Requires the same keyword used during encryption.
Formula: P[i] = (C[i] - K[i]) mod 26
"""

def generate_key(msg, key):
    """Extend or trim the key to match the message length."""
    key = list(key.upper())
    idx = 0
    while len(key) < len(msg):
        key.append(key[idx % len(key)])
        idx += 1
    return ''.join(key[:len(msg)])


def decrypt_vigenere(cipher, key):
    key_full = generate_key(cipher, key)
    decrypted = []
    for i, char in enumerate(cipher):
        if char.isupper():
            dec = chr((ord(char) - ord(key_full[i]) + 26) % 26 + ord('A'))
            decrypted.append(dec)
        elif char.islower():
            dec = chr((ord(char) - ord(key_full[i].lower()) + 26) % 26 + ord('a'))
            decrypted.append(dec)
        else:
            decrypted.append(char)
    return ''.join(decrypted)


if __name__ == '__main__':
    cipher = "rijvs"   # encrypted "hello" with key "key"
    key    = "key"
    print("Cipher   :", cipher)
    print("Decrypted:", decrypt_vigenere(cipher, key))
