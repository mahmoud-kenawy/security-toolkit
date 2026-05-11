"""
SimpleSubstitutionCipherDecrypt.py
Decryption for Simple Substitution Cipher.
Reverses the key mapping: find the ciphertext char in the key alphabet
and return the corresponding standard alphabet letter.
"""

LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'


def decrypt(text, key):
    key = key.upper()
    translated = ''
    for symbol in text:
        if symbol.upper() in key:
            idx = key.find(symbol.upper())
            translated += LETTERS[idx] if symbol.isupper() else LETTERS[idx].lower()
        else:
            translated += symbol
    return translated


if __name__ == '__main__':
    key    = 'POIUYTRWEQASDFGHJKLMNBVCXZ'
    cipher = 'wtssg'           # encrypted form of "hello"
    print("Cipher   :", cipher)
    print("Decrypted:", decrypt(cipher, key))
