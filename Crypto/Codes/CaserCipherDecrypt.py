"""
CaserCipherDecrypt.py
Decryption for Caesar Cipher — reverses the shift to recover the original plaintext.
"""

def decrypt(text, key):
    result = ""
    for char in text:
        if char.isupper():
            result += chr((ord(char) - key - 65) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) - key - 97) % 26 + 97)
        else:
            result += char
    return result


if __name__ == '__main__':
    cipher = "EXXEGOEXSRGI"
    key = 4
    print("Cipher   : " + cipher)
    print("Decrypted: " + decrypt(cipher, key))
