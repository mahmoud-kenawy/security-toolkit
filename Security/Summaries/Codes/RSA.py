import random
from sympy import isprime
# RSA Functions
def generate_prime(bits):
    while True:
        num = random.getrandbits(bits)
        if isprime(num):
            return num

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def generate_keys(bit_length=10):
    p = generate_prime(bit_length)
    q = generate_prime(bit_length)
    n = p * q
    euler = (p - 1) * (q - 1)
    
    e = random.randrange(2, euler)
    while gcd(e, euler) != 1:
        e = random.randrange(2, euler)
    
    for i in range(1, euler):
        if (i * e) % euler == 1:
            d = i
            break
    
    return n, e, d

# Generate RSA keys once at startup
n, e, d = generate_keys(bit_length=10)

def encrypt_message():
    message = entry_1.get()
    
    if not message:
        messagebox.showwarning("Input Error", "Please enter a message to encrypt!")
        return
    
    try:
        # Convert message to ASCII numbers
        message_ascii = [ord(ch) for ch in message]
        
        # Encrypt each character
        cipher = [(m ** e) % n for m in message_ascii]
        
        # Display encrypted message in entry_2
        entry_2.delete("1.0", "end")
        entry_2.insert("1.0", str(cipher))
        
        # Clear entry_3 (decrypted text)
        entry_3.delete("1.0", "end")
        
        messagebox.showinfo("Success", "Message encrypted successfully!")
    except Exception as ex:
        messagebox.showerror("Error", f"Encryption failed: {str(ex)}")

def decrypt_message():
    cipher_text = entry_2.get("1.0", "end-1c").strip()
    
    if not cipher_text:
        messagebox.showwarning("Input Error", "No encrypted message to decrypt!")
        return
    
    try:
        # Convert string representation of list back to list
        cipher = eval(cipher_text)
        
        # Decrypt each character
        decrypted = [(c ** d) % n for c in cipher]
        decrypted_text = ''.join(chr(num) for num in decrypted)
        
        # Display decrypted message in entry_3
        entry_3.delete("1.0", "end")
        entry_3.insert("1.0", decrypted_text)
        
        messagebox.showinfo("Success", "Message decrypted successfully!")
    except Exception as ex:
        messagebox.showerror("Error", f"Decryption failed: {str(ex)}")