def main():
    myMessage = 'hello'
    myKey = 5
    ciphertext = encryptMessage(myKey, myMessage)
    print("Cipher Text is")
    print(ciphertext + '|')

def encryptMessage(key, message):
    ciphertext = [''] * key
    print(len(message))
    for col in range(key):
        position = col
        while position < len(message):
            ciphertext[col] += message[position]
            position += key
        print(ciphertext)
    return ''.join(ciphertext) #Cipher text