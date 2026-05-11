"""
MultiplicativeCipherDecrypt.py
Decryption for Multiplicative Cipher.
Formula: P = (C * key_inverse) mod 26
The key must be coprime to 26 (valid keys: 3,5,7,9,11,15,17,19,21,23,25).
"""

def mod_inverse(key, mod=26):
    """Find the modular inverse of key mod 26."""
    for i in range(1, mod):
        if (key * i) % mod == 1:
            return i
    raise ValueError(
        f"Key {key} has no modular inverse mod 26. "
        "Choose a key coprime to 26 (e.g. 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25)."
    )


def decrypt(cipher_text, key):
    inv_key = mod_inverse(key)
    plain_text = ""
    for char in cipher_text:
        if char.isalpha():
            char_upper = char.upper()
            dec_char = chr(((ord(char_upper) - ord('A')) * inv_key) % 26 + ord('A'))
            plain_text += dec_char if char.isupper() else dec_char.lower()
        else:
            plain_text += char
    return plain_text


if __name__ == '__main__':
    cipher = "XCZZU"
    key = 7
    print("Cipher   :", cipher)
    print("Decrypted:", decrypt(cipher, key))
