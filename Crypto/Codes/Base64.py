import base64

s = "Linus".encode()
print(s)
b = base64.b64encode(s)
print(b)
print(base64.b64decode(b).decode())