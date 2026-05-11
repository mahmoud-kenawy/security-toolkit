def encrypt(plain_text, key):
    cipher_text = ""
    for char in plain_text:
        if char.isalpha():
            char = char.upper()
            encrypted_char = chr(((ord(char) - ord('A')) * key) % 26 + ord('A'))
            cipher_text += encrypted_char
        else:
            cipher_text += char
    return cipher_text

plain_text = "HELLO"
key = 7
cipher_text = encrypt(plain_text, key)
print("Encrypted:", cipher_text)