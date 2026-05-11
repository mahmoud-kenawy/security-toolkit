"""
Security Toolkit - A Beautiful Tkinter Application for Cryptographic Algorithms
Integrates RSA, DES Key Generation, and S-DES Encryption/Decryption
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import random
import struct
import math
import hashlib
import jwt
import datetime

# ==================== FULL DES TABLES & UTILS ====================

# Initial Permutation Table
# Initial Permutation Table
DES_IP = [58, 50, 42, 34, 26, 18, 10, 2,
				60, 52, 44, 36, 28, 20, 12, 4,
				62, 54, 46, 38, 30, 22, 14, 6,
				64, 56, 48, 40, 32, 24, 16, 8,
				57, 49, 41, 33, 25, 17, 9, 1,
				59, 51, 43, 35, 27, 19, 11, 3,
				61, 53, 45, 37, 29, 21, 13, 5,
				63, 55, 47, 39, 31, 23, 15, 7]

# Expansion D-box Table
DES_EXP_D = [32, 1, 2, 3, 4, 5, 4, 5,
		6, 7, 8, 9, 8, 9, 10, 11,
		12, 13, 12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21, 20, 21,
		22, 23, 24, 25, 24, 25, 26, 27,
		28, 29, 28, 29, 30, 31, 32, 1]

# Straight Permutation Table
DES_PER = [16, 7, 20, 21,
	29, 12, 28, 17,
	1, 15, 23, 26,
	5, 18, 31, 10,
	2, 8, 24, 14,
	32, 27, 3, 9,
	19, 13, 30, 6,
	22, 11, 4, 25]

# S-box Table
DES_SBOX = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
		[0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
		[4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
		[15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

		[[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
		[3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
		[0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
		[13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

		[[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
		[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
		[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
		[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

		[[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
		[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
		[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
		[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

		[[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
		[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
		[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
		[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

		[[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
		[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
		[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
		[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

		[[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
		[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
		[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
		[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

		[[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
		[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
		[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
		[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

# Final Permutation Table
DES_FINAL_PER = [40, 8, 48, 16, 56, 24, 64, 32,
			39, 7, 47, 15, 55, 23, 63, 31,
			38, 6, 46, 14, 54, 22, 62, 30,
			37, 5, 45, 13, 53, 21, 61, 29,
			36, 4, 44, 12, 52, 20, 60, 28,
			35, 3, 43, 11, 51, 19, 59, 27,
			34, 2, 42, 10, 50, 18, 58, 26,
			33, 1, 41, 9, 49, 17, 57, 25]

# Key Parity Table (PC-1)
DES_KEY_P = [57, 49, 41, 33, 25, 17, 9,
		1, 58, 50, 42, 34, 26, 18,
		10, 2, 59, 51, 43, 35, 27,
		19, 11, 3, 60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15,
		7, 62, 54, 46, 38, 30, 22,
		14, 6, 61, 53, 45, 37, 29,
		21, 13, 5, 28, 20, 12, 4]

# Key Shift Table
DES_SHIFT_TABLE = [1, 1, 2, 2,
			2, 2, 2, 2,
			1, 2, 2, 2,
			2, 2, 2, 1]

# Key Compression Table (PC-2)
DES_KEY_COMP = [14, 17, 11, 24, 1, 5,
			3, 28, 15, 6, 21, 10,
			23, 19, 12, 4, 26, 8,
			16, 7, 27, 20, 13, 2,
			41, 52, 31, 37, 47, 55,
			30, 40, 51, 45, 33, 48,
			44, 49, 39, 56, 34, 53,
			46, 42, 50, 36, 29, 32]


def is_prime(n):
    """Check if a number is prime"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    # Check odd divisors up to sqrt(n)
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


class FullDES:
    @staticmethod
    def hex2bin(s):
        mp = {'0': "0000",
              '1': "0001",
              '2': "0010",
              '3': "0011",
              '4': "0100",
              '5': "0101",
              '6': "0110",
              '7': "0111",
              '8': "1000",
              '9': "1001",
              'A': "1010",
              'B': "1011",
              'C': "1100",
              'D': "1101",
              'E': "1110",
              'F': "1111"}
        bin_str = ""
        for i in range(len(s)):
            bin_str += mp[s[i].upper()]
        return bin_str

    @staticmethod
    def bin2hex(s):
        mp = {"0000": '0',
              "0001": '1',
              "0010": '2',
              "0011": '3',
              "0100": '4',
              "0101": '5',
              "0110": '6',
              "0111": '7',
              "1000": '8',
              "1001": '9',
              "1010": 'A',
              "1011": 'B',
              "1100": 'C',
              "1101": 'D',
              "1110": 'E',
              "1111": 'F'}
        hex_str = ""
        for i in range(0, len(s), 4):
            ch = ""
            ch = ch + s[i]
            ch = ch + s[i + 1]
            ch = ch + s[i + 2]
            ch = ch + s[i + 3]
            hex_str = hex_str + mp[ch]
        return hex_str

    @staticmethod
    def bin2dec(binary):
        binary1 = binary
        decimal, i, n = 0, 0, 0
        while(binary != 0):
            dec = binary % 10
            decimal = decimal + dec * pow(2, i)
            binary = binary//10
            i += 1
        return decimal

    @staticmethod
    def dec2bin(num):
        res = bin(num).replace("0b", "")
        if(len(res) % 4 != 0):
            div = len(res) / 4
            div = int(div)
            counter = (4 * (div + 1)) - len(res)
            for i in range(0, counter):
                res = '0' + res
        return res

    @staticmethod
    def permute(k, arr, n):
        permutation = ""
        for i in range(0, n):
            permutation = permutation + k[arr[i] - 1]
        return permutation

    @staticmethod
    def shift_left(k, nth_shifts):
        s = ""
        for i in range(nth_shifts):
            for j in range(1, len(k)):
                s = s + k[j]
            s = s + k[0]
            k = s
            s = ""
        return k

    @staticmethod
    def xor(a, b):
        ans = ""
        for i in range(len(a)):
            if a[i] == b[i]:
                ans = ans + "0"
            else:
                ans = ans + "1"
        return ans

    @staticmethod
    def generate_keys(key_hex):
        key = FullDES.hex2bin(key_hex)
        key = FullDES.permute(key, DES_KEY_P, 56)
        left = key[0:28]
        right = key[28:56]
        rkb = []
        rk = []
        for i in range(0, 16):
            left = FullDES.shift_left(left, DES_SHIFT_TABLE[i])
            right = FullDES.shift_left(right, DES_SHIFT_TABLE[i])
            combine_str = left + right
            round_key = FullDES.permute(combine_str, DES_KEY_COMP, 48)
            rkb.append(round_key)
            rk.append(FullDES.bin2hex(round_key))
        return rkb, rk

    @staticmethod
    def encrypt_logic(pt, rkb, rk):
        pt = FullDES.hex2bin(pt)
        
        # Initial Permutation
        pt = FullDES.permute(pt, DES_IP, 64)
        logs = []
        logs.append(f"After initial permutation {FullDES.bin2hex(pt)}")
        
        left = pt[0:32]
        right = pt[32:64]
        
        for i in range(0, 16):
            right_expanded = FullDES.permute(right, DES_EXP_D, 48)
            xor_x = FullDES.xor(right_expanded, rkb[i])
            sbox_str = ""
            for j in range(0, 8):
                row_bits = xor_x[j * 6] + xor_x[j * 6 + 5]
                col_bits = xor_x[j * 6 + 1] + xor_x[j * 6 + 2] + xor_x[j * 6 + 3] + xor_x[j * 6 + 4]
                row = FullDES.bin2dec(int(row_bits))
                col = FullDES.bin2dec(int(col_bits))
                val = DES_SBOX[j][row][col]
                sbox_str = sbox_str + FullDES.dec2bin(val)
                
            sbox_str = FullDES.permute(sbox_str, DES_PER, 32)
            result = FullDES.xor(left, sbox_str)
            left = result
            
            if i != 15:
                left, right = right, left
            
            logs.append(f"Round  {i+1:<4} {FullDES.bin2hex(left):<10} {FullDES.bin2hex(right):<10} {rk[i]}")
            
        combine = left + right
        cipher_text = FullDES.permute(combine, DES_FINAL_PER, 64)
        return FullDES.bin2hex(cipher_text), logs

    @staticmethod
    def encrypt(pt, key):
        try:
            rkb, rk = FullDES.generate_keys(key)
            ct, logs = FullDES.encrypt_logic(pt, rkb, rk)
            logs.append(f"Cipher Text :  {ct}")
            return ct, logs
        except Exception as e:
            return f"Error: {str(e)}", [str(e)]

    @staticmethod
    def decrypt(ct, key):
        try:
            rkb, rk = FullDES.generate_keys(key)
            rkb_rev = rkb[::-1]
            rk_rev = rk[::-1]
            pt, logs = FullDES.encrypt_logic(ct, rkb_rev, rk_rev)
            logs.append(f"Plain Text :  {pt}")
            return pt, logs
        except Exception as e:
            return f"Error: {str(e)}", [str(e)]

    @staticmethod
    def decrypt_old(ct, key):
        # Similar logic but with reversed keys
        ct = FullDES.hex2bin(ct)
        key = FullDES.hex2bin(key)

        # Key generation
        key = FullDES.permute(key, DES_KEY_P, 56)
        left = key[0:28]
        right = key[28:56]
        
        rkb = []
        for i in range(0, 16):
            left = FullDES.shift_left(left, DES_SHIFT_TABLE[i])
            right = FullDES.shift_left(right, DES_SHIFT_TABLE[i])
            combine_str = left + right
            round_key = FullDES.permute(combine_str, DES_KEY_COMP, 48)
            rkb.append(round_key)

        rkb = rkb[::-1] # Reverse keys for decryption

        # Decryption
        ct = FullDES.permute(ct, DES_IP, 64)
        
        # Log Initial Permutation for Decryption
        logs = []
        logs.append(f"After initial permutation {FullDES.bin2hex(ct)}")
        
        left = ct[0:32]
        right = ct[32:64]
        
        # Re-generate hex keys for logging in reverse, assuming rkb is already reversed
        rk_rev = [FullDES.bin2hex(k) for k in rkb]

        for i in range(0, 16):
            right_expanded = FullDES.permute(right, DES_EXP_D, 48)
            xor_x = FullDES.xor(right_expanded, rkb[i])
            sbox_str = ""
            for j in range(0, 8):
                row = FullDES.bin2dec(xor_x[j * 6] + xor_x[j * 6 + 5])
                col = FullDES.bin2dec(xor_x[j * 6 + 1:j * 6 + 5])
                val = DES_SBOX[j][row][col]
                sbox_str += FullDES.dec2bin(val)
                
            sbox_str = FullDES.permute(sbox_str, DES_PER, 32)
            result = FullDES.xor(left, sbox_str)
            left = result
            
            if i != 15:
                left, right = right, left
            
            logs.append(f"Round  {i+1:<4} {FullDES.bin2hex(left):<10} {FullDES.bin2hex(right):<10} {rk_rev[i]}")

        combine = left + right
        plain_text = FullDES.permute(combine, DES_FINAL_PER, 64)
        logs.append(f"Plain Text :  {FullDES.bin2hex(plain_text)}")
        return FullDES.bin2hex(plain_text), logs


class SecurityToolkit:
    def __init__(self, root):
        self.root = root

        self.root.title("🔐 Security Toolkit")
        self.root.geometry("900x700")
        self.root.configure(bg="#0a0e27")
        
        # Generate RSA keys at startup
        self.rsa_n, self.rsa_e, self.rsa_d = self.generate_rsa_keys(bit_length=10)
        
        # Configure custom style
        self.setup_styles()
        
        # Main container for page switching
        self.main_container = ttk.Frame(self.root, style='Dark.TFrame')
        self.main_container.pack(fill='both', expand=True)
        
        # Load explanations
        self.explanations = self.load_explanations()
        
        # Start with landing page
        self.create_landing_page()
        self.create_status_bar()
        
    def setup_styles(self):
        """Configure custom ttk styles for security theme"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure notebook
        style.configure('TNotebook', background='#0a0e27', borderwidth=0)
        style.configure('TNotebook.Tab', 
                       background='#16213e', 
                       foreground='#00d4ff',
                       padding=[18, 5],
                       font=('Consolas', 10, 'bold'))
        style.map('TNotebook.Tab',
                 background=[('selected', '#1a1a2e')],
                 foreground=[('selected', '#0f0')])
        
        # Configure frames
        style.configure('Dark.TFrame', background='#0a0e27')
        style.configure('Card.TFrame', background='#16213e', relief='raised')
        
        # Configure labels
        style.configure('Title.TLabel', 
                       background='#0a0e27',
                       foreground='#0f0',
                       font=('Consolas', 16, 'bold'))
        style.configure('Header.TLabel',
                       background='#16213e',
                       foreground='#00d4ff',
                       font=('Consolas', 11, 'bold'))
        style.configure('Info.TLabel',
                       background='#16213e',
                       foreground='#e0e0e0',
                       font=('Consolas', 9))
        
        # Configure buttons
        style.configure('Action.TButton',
                       background='#0f0',
                       foreground='#000',
                       font=('Consolas', 10, 'bold'),
                       padding=[10, 5])
        style.map('Action.TButton',
                 background=[('active', '#00ff00'), ('pressed', '#00cc00')])
        
        style.map('Secondary.TButton',
                 background=[('active', '#00e5ff'), ('pressed', '#00b0cc')])
        
    def load_explanations(self):
        """Load and parse explanation files from Summaries folder"""
        explanations = {}
        # Assuming 'Summaries' is a sibling directory to the script's directory
        import os
        summary_dir = os.path.join(os.path.dirname(__file__), 'Summaries')
        
        if not os.path.exists(summary_dir):
            print(f"Summaries directory not found: {summary_dir}")
            return {}
            
        try:
            # Parse File 1 (SDES, DES)
            file1_path = os.path.join(summary_dir, '1.txt')
            if os.path.exists(file1_path):
                with open(file1_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    parts = content.split('2. DES')
                    if len(parts) > 0: 
                        sdes_text = parts[0].strip()
                        if sdes_text.startswith('1. SDES'):
                            sdes_text = sdes_text.replace('1. SDES', 'SDES', 1)
                        explanations['SDES'] = sdes_text
                    if len(parts) > 1: explanations['DES'] = 'DES' + parts[1].strip()
                
            # Parse File 2 (RSA, Diffie-Hellman)
            file2_path = os.path.join(summary_dir, '2.txt')
            if os.path.exists(file2_path):
                with open(file2_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    parts = content.split('4. Diffie-Hellman')
                    if len(parts) > 0: 
                        rsa_text = parts[0].strip()
                        # Handle specific formatting in file
                        if '، 3 RSA' in rsa_text:
                            rsa_text = rsa_text.replace('، 3 RSA', 'RSA', 1)
                        elif rsa_text.startswith('3. RSA'):
                            rsa_text = rsa_text.replace('3. RSA', 'RSA', 1)
                        explanations['RSA'] = rsa_text
                    if len(parts) > 1: explanations['Diffie-Hellman'] = 'Diffie-Hellman' + parts[1].strip()
                
            # Parse File 3 (MD5, SHA-1, DSS)
            file3_path = os.path.join(summary_dir, '3.txt')
            if os.path.exists(file3_path):
                with open(file3_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    parts = content.split('6. SHA-1')
                    if len(parts) > 0: 
                        md5_text = parts[0].strip()
                        if md5_text.startswith('5. MD5'):
                            md5_text = md5_text.replace('5. MD5', 'MD5', 1)
                        explanations['MD5'] = md5_text
                    remain = parts[1] if len(parts) > 1 else ""
                    
                    parts2 = remain.split('7. DSS')
                    if len(parts2) > 0: explanations['SHA-1'] = 'SHA-1' + parts2[0].strip()
                    if len(parts2) > 1: explanations['DSS'] = 'DSS' + parts2[1].strip()

            # Parse JWT Explanation
            jwt_path = os.path.join(summary_dir, 'jwtexplain.txt')
            if os.path.exists(jwt_path):
                with open(jwt_path, 'r', encoding='utf-8') as f:
                    explanations['JWT'] = f.read().strip()
                
        except Exception as e:
            print(f"Error loading summaries: {e}")
            
        return explanations

    def create_landing_page(self):
        """Create the main landing page"""
        for widget in self.main_container.winfo_children():
            widget.destroy()
            
        landing_frame = ttk.Frame(self.main_container, style='Dark.TFrame')
        landing_frame.pack(fill='both', expand=True)
        
        # Center content
        center_frame = ttk.Frame(landing_frame, style='Dark.TFrame')
        center_frame.place(relx=0.5, rely=0.5, anchor='center')
        
        # Title
        tk.Label(center_frame, text="🔐 SECURITY TOOLKIT", 
                font=('Consolas', 32, 'bold'),
                bg='#0a0e27', fg='#00ff00').pack(pady=20)
                
        tk.Label(center_frame, text="Select operation mode:",
                font=('Consolas', 14),
                bg='#0a0e27', fg='#888').pack(pady=(0, 30))
                
        # Big Buttons
        btn_frame = ttk.Frame(center_frame, style='Dark.TFrame')
        btn_frame.pack()
        
        tk.Button(btn_frame, text="🛠️ CODES\n(Run Algorithms)", 
                 font=('Consolas', 16, 'bold'),
                 bg='#16213e', fg='#00d4ff',
                 activebackground='#00d4ff', activeforeground='#000',
                 width=20, height=5, bd=0, cursor='hand2',
                 command=self.show_codes_view).pack(side='left', padx=20)
                 
        tk.Button(btn_frame, text="📚 EXPLANATION\n(Learn Concepts)", 
                 font=('Consolas', 16, 'bold'),
                 bg='#16213e', fg='#ff6b6b',
                 activebackground='#ff6b6b', activeforeground='#000',
                 width=20, height=5, bd=0, cursor='hand2',
                 command=self.show_explanation_view).pack(side='left', padx=20)

    def show_codes_view(self):
        """Switch to Codes view"""
        for widget in self.main_container.winfo_children():
            widget.destroy()
            
        self.create_header(self.main_container, "Codes")
        self.create_notebook(self.main_container)
        
    def show_explanation_view(self):
        """Switch to Explanation view"""
        for widget in self.main_container.winfo_children():
            widget.destroy()
            
        self.create_header(self.main_container, "Explanation")
        
        # Explanation Notebook
        exp_notebook = ttk.Notebook(self.main_container)
        exp_notebook.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
        # Map tabs to keys
        algo_map = {
            'RSA': 'RSA',
            'DES / Full DES': 'DES',
            'S-DES': 'SDES',
            'MD5 / Full MD5': 'MD5',
            'SHA-1 / SHA Family': 'SHA-1',
            'DSS': 'DSS',
            'Diffie-Hellman': 'Diffie-Hellman',
            'JWT': 'JWT'
        }
        
        # Keep references to images to prevent GC
        self.msg_images = []
        
        import os
        img_dir = os.path.join(os.path.dirname(__file__), 'Summaries', 'images')
        
        img_map = {
            'RSA': 'rsa.png',
            'DES': 'des.png',
            'SDES': 'sdes.png',
            'MD5': 'md5.png',
            'SHA-1': 'sha1.png',
            'Diffie-Hellman': 'dh.png',
            'DSS': 'dss.png',
            'JWT': 'structure of JWT.webp'
        }
        
        for name, key in algo_map.items():
            tab_frame = ttk.Frame(exp_notebook, style='Dark.TFrame')
            exp_notebook.add(tab_frame, text=name)
            
            # Use PanedWindow or just frames side-by-side
            # Left: Text, Right: Image
            
            content_frame = ttk.Frame(tab_frame, style='Dark.TFrame')
            content_frame.pack(fill='both', expand=True, padx=10, pady=10)
            
            # Text area (Left)
            text_area = scrolledtext.ScrolledText(content_frame, bg='#0a0e27', fg='#fff', 
                                                font=('Consolas', 11), padx=20, pady=20, wrap='word')
            text_area.pack(side='left', fill='both', expand=True)
            
            content = self.explanations.get(key, "Explanation not found.")
            text_area.insert('end', content)
            text_area.config(state='disabled')
            
            # Image area (Right)
            if key in img_map:
                img_path = os.path.join(img_dir, img_map[key])
                if os.path.exists(img_path):
                    try:
                        from PIL import Image, ImageTk
                        
                        pil_img = Image.open(img_path)
                        
                        # Resize for side panel (width ~400px)
                        orig_w, orig_h = pil_img.size
                        target_w = 400
                        target_h = int(orig_h * (target_w / orig_w))
                        
                        # Limit height as well if too tall
                        if target_h > 500:
                            target_h = 500
                            target_w = int(orig_w * (target_h / orig_h))
                        
                        pil_img = pil_img.resize((target_w, target_h), Image.Resampling.LANCZOS)
                        
                        tk_img = ImageTk.PhotoImage(pil_img)
                        self.msg_images.append(tk_img)
                        
                        img_label = ttk.Label(content_frame, image=tk_img, background='#0a0e27')
                        img_label.pack(side='right', anchor='n', padx=(10, 0))
                        
                    except Exception as e:
                        print(f"Error loading image {img_path}: {e}")
            
    def create_header(self, parent, view_name):
        """Create application header with back button"""
        header_frame = ttk.Frame(parent, style='Dark.TFrame', height=80)
        header_frame.pack(fill='x', padx=10, pady=10)
        
        # Back Button
        # Back Button
        ttk.Button(header_frame, text="⬅ Back", style='Secondary.TButton',
                   command=self.create_landing_page).place(x=0, y=0)
        
        # Center Title Container
        title_container = ttk.Frame(header_frame, style='Dark.TFrame')
        title_container.pack(side='top')
        
        # Main Title
        title = ttk.Label(title_container, 
                         text=f"🔐 SECURITY TOOLKIT - {view_name.upper()}",
                         style='Title.TLabel')
        title.pack()
        
        # Subtitle
        if view_name.lower() == "codes":
            sub_text = "(Run Algorithms)"
        elif view_name.lower() == "explanation":
            sub_text = "(Learn Concepts)"
        else:
            sub_text = "Cryptographic Algorithms"
            
        subtitle = tk.Label(title_container,
                           text=sub_text,
                           bg='#0a0e27',
                           fg='#00d4ff',
                           font=('Consolas', 10, 'bold'))
        subtitle.pack()
    
    def create_notebook(self, parent):
        """Create tabbed interface"""
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
        # Create tabs
        self.create_rsa_tab()
        self.create_des_tab()
        self.create_full_des_tab()
        self.create_sdes_tab()
        self.create_md5_tab()
        self.create_sha1_tab()
        self.create_sha_family_tab()
        self.create_full_md5_tab()
        self.create_dss_tab()
        self.create_hellman_tab()
        self.create_jwt_tab()
    
    def create_status_bar(self):
        """Create status bar at bottom"""
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Label(self.root,
                             textvariable=self.status_var,
                             bg='#16213e',
                             fg='#0f0',
                             font=('Consolas', 10),
                             anchor='w',
                             padx=18,
                             pady=5)
        status_bar.pack(side='bottom', fill='x')
    
    def set_status(self, message, timeout=3000):
        """Update status bar message"""
        # Cancel previous timer if it exists
        if hasattr(self, '_status_timer') and self._status_timer:
            self.root.after_cancel(self._status_timer)
            self._status_timer = None
            
        self.status_var.set(f"⚡ {message}")
        
        if timeout > 0:
            self._status_timer = self.root.after(timeout, lambda: self.status_var.set("Ready"))
            
    # ==================== RSA TAB ====================
    
    def create_rsa_tab(self):
        """Create RSA encryption/decryption tab"""
        rsa_frame = ttk.Frame(self.notebook, style='Dark.TFrame')
        self.notebook.add(rsa_frame, text='🔑 RSA')
        
        # Key information frame
        key_frame = ttk.Frame(rsa_frame, style='Card.TFrame')
        key_frame.pack(fill='x', padx=15, pady=15)
        
        ttk.Label(key_frame, text="RSA Key Information", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        self.rsa_key_info = tk.Text(key_frame, height=3, width=60, 
                                    bg='#0a0e27', fg='#00d4ff',
                                    font=('Consolas', 9),
                                    relief='flat', padx=10, pady=5)
        self.rsa_key_info.pack(padx=10, pady=(0, 5))
        self.update_rsa_key_display()
        
        btn_frame = ttk.Frame(key_frame, style='Card.TFrame')
        btn_frame.pack(pady=(0, 10))
        
        ttk.Button(btn_frame, text="🔄 Regenerate Keys", 
                  style='Secondary.TButton',
                  command=self.regenerate_rsa_keys).pack(side='left', padx=5)
        
        # Message input
        input_frame = ttk.Frame(rsa_frame, style='Card.TFrame')
        input_frame.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        
        # Message input
        input_header_frame = ttk.Frame(input_frame, style='Card.TFrame')
        input_header_frame.pack(fill='x', padx=10, pady=(10, 5))
        
        ttk.Label(input_header_frame, text="Plaintext Message", style='Header.TLabel').pack(side='left')
        
        ttk.Button(input_header_frame, text="📂 Load File", 
                  style='Secondary.TButton',
                  command=lambda: self.load_file_to_widget(self.rsa_plaintext)).pack(side='right')
        
        self.rsa_plaintext = scrolledtext.ScrolledText(input_frame, height=4, width=60,
                                                       bg='#0a0e27', fg='#0f0',
                                                       font=('Consolas', 10),
                                                       relief='flat', padx=10, pady=5,
                                                       insertbackground='#0f0')
        self.rsa_plaintext.pack(padx=10, pady=(0, 10))
        
        # Encrypted output
        ttk.Label(input_frame, text="Encrypted Ciphertext", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        cipher_container = ttk.Frame(input_frame, style='Card.TFrame')
        cipher_container.pack(fill='x', padx=10)
        
        self.rsa_ciphertext = scrolledtext.ScrolledText(cipher_container, height=4, width=50,
                                                        bg='#0a0e27', fg='#ff6b6b',
                                                        font=('Consolas', 9),
                                                        relief='flat', padx=10, pady=5,
                                                        state='disabled')
        self.rsa_ciphertext.pack(side='left', fill='both', expand=True)
        
        ttk.Button(cipher_container, text="📋", 
                  style='Secondary.TButton',
                  command=lambda: self.copy_to_clipboard(self.rsa_ciphertext)).pack(side='left', padx=(5, 0))

        ttk.Button(cipher_container, text="💾", 
                  style='Secondary.TButton',
                  command=lambda: self.save_text_to_file(self.rsa_ciphertext.get('1.0', 'end-1c'))).pack(side='left', padx=(5, 0))
        
        # Decrypted output
        ttk.Label(input_frame, text="Decrypted Message", style='Header.TLabel').pack(anchor='w', padx=10, pady=(15, 5))
        
        decrypt_container = ttk.Frame(input_frame, style='Card.TFrame')
        decrypt_container.pack(fill='x', padx=10, pady=(0, 10))
        
        self.rsa_decrypted = scrolledtext.ScrolledText(decrypt_container, height=4, width=50,
                                                       bg='#0a0e27', fg='#0f0',
                                                       font=('Consolas', 10),
                                                       relief='flat', padx=10, pady=5,
                                                       state='disabled')
        self.rsa_decrypted.pack(side='left', fill='both', expand=True)
        
        ttk.Button(decrypt_container, text="📋",
                  style='Secondary.TButton',
                  command=lambda: self.copy_to_clipboard(self.rsa_decrypted)).pack(side='left', padx=(5, 0))

        ttk.Button(decrypt_container, text="💾",
                  style='Secondary.TButton',
                  command=lambda: self.save_text_to_file(self.rsa_decrypted.get('1.0', 'end-1c'))).pack(side='left', padx=(5, 0))
        
        # Action buttons
        action_frame = ttk.Frame(input_frame, style='Card.TFrame')
        action_frame.pack(pady=(5, 10))
        
        ttk.Button(action_frame, text="🔒 ENCRYPT", 
                  style='Action.TButton',
                  command=self.rsa_encrypt).pack(side='left', padx=5)
        
        ttk.Button(action_frame, text="🔓 DECRYPT",
                  style='Action.TButton',
                  command=self.rsa_decrypt).pack(side='left', padx=5)
    
    # RSA Algorithm Functions
    def generate_prime(self, bits):
        """Generate a prime number with given bit length"""
        while True:
            num = random.getrandbits(bits)
            if is_prime(num):
                return num
    
    def gcd(self, a, b):
        """Calculate greatest common divisor"""
        while b:
            a, b = b, a % b
        return a
    
    def generate_rsa_keys(self, bit_length=10):
        """Generate RSA key pair"""
        p = self.generate_prime(bit_length)
        q = self.generate_prime(bit_length)
        n = p * q
        euler = (p - 1) * (q - 1)
        
        e = random.randrange(2, euler)
        while self.gcd(e, euler) != 1:
            e = random.randrange(2, euler)
        
        for i in range(1, euler):
            if (i * e) % euler == 1:
                d = i
                break
        
        return n, e, d
    
    def update_rsa_key_display(self):
        """Update RSA key information display"""
        self.rsa_key_info.config(state='normal')
        self.rsa_key_info.delete('1.0', 'end')
        self.rsa_key_info.insert('1.0', 
            f"Public Key (n, e):  n = {self.rsa_n}, e = {self.rsa_e}\n"
            f"Private Key (d):    d = {self.rsa_d}\n"
            f"Key Strength:       {self.rsa_n.bit_length()} bits")
        self.rsa_key_info.config(state='disabled')
    
    def regenerate_rsa_keys(self):
        """Regenerate RSA keys"""
        self.rsa_n, self.rsa_e, self.rsa_d = self.generate_rsa_keys(bit_length=10)
        self.update_rsa_key_display()
        self.set_status("New RSA keys generated successfully")
    
    def rsa_encrypt(self):
        """Encrypt message using RSA"""
        message = self.rsa_plaintext.get('1.0', 'end-1c')
        
        if not message:
            messagebox.showwarning("Input Error", "Please enter a message to encrypt!")
            return
        
        try:
            # Convert message to ASCII numbers
            message_ascii = [ord(ch) for ch in message]
            
            # Encrypt each character
            cipher = [(m ** self.rsa_e) % self.rsa_n for m in message_ascii]
            
            # Display encrypted message
            self.rsa_ciphertext.config(state='normal')
            self.rsa_ciphertext.delete('1.0', 'end')
            self.rsa_ciphertext.insert('1.0', str(cipher))
            self.rsa_ciphertext.config(state='disabled')
            
            # Clear decrypted text
            self.rsa_decrypted.config(state='normal')
            self.rsa_decrypted.delete('1.0', 'end')
            self.rsa_decrypted.config(state='disabled')
            
            self.set_status("Message encrypted successfully")
        except Exception as ex:
            messagebox.showerror("Error", f"Encryption failed: {str(ex)}")
    
    def rsa_decrypt(self):
        """Decrypt message using RSA"""
        cipher_text = self.rsa_ciphertext.get('1.0', 'end-1c').strip()
        
        if not cipher_text:
            messagebox.showwarning("Input Error", "No encrypted message to decrypt!")
            return
        
        try:
            # Convert string representation of list back to list
            cipher = eval(cipher_text)
            
            # Decrypt each character
            decrypted = [(c ** self.rsa_d) % self.rsa_n for c in cipher]
            decrypted_text = ''.join(chr(num) for num in decrypted)
            
            # Display decrypted message
            self.rsa_decrypted.config(state='normal')
            self.rsa_decrypted.delete('1.0', 'end')
            self.rsa_decrypted.insert('1.0', decrypted_text)
            self.rsa_decrypted.config(state='disabled')
            
            self.set_status("Message decrypted successfully")
        except Exception as ex:
            messagebox.showerror("Error", f"Decryption failed: {str(ex)}")
    
    # ==================== DES TAB ====================
    
    def create_des_tab(self):
        """Create DES 16-round key generation tab"""
        des_frame = ttk.Frame(self.notebook, style='Dark.TFrame')
        self.notebook.add(des_frame, text='🔐 DES')
        
        # Input frame
        input_frame = ttk.Frame(des_frame, style='Card.TFrame')
        input_frame.pack(fill='x', padx=15, pady=15)
        
        ttk.Label(input_frame, text="DES Key Generator (16 Rounds)", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        ttk.Label(input_frame, text="Enter 16-character hexadecimal key (0-9, A-F):", 
                 style='Info.TLabel').pack(anchor='w', padx=10, pady=(5, 5))
        
        key_input_frame = ttk.Frame(input_frame, style='Card.TFrame')
        key_input_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        self.des_key_entry = tk.Entry(key_input_frame, 
                                      bg='#0a0e27', fg='#0f0',
                                      font=('Consolas', 12, 'bold'),
                                      insertbackground='#0f0',
                                      relief='flat',
                                      width=40)
        self.des_key_entry.pack(side='left', padx=(0, 10), pady=5, ipady=5)
        self.des_key_entry.insert(0, "133457799BBCDFF1")
        
        ttk.Button(key_input_frame, text="📂", width=3,
                   style='Secondary.TButton',
                   command=lambda: self.load_file_to_widget(self.des_key_entry)).pack(side='left', padx=(0, 5))

        ttk.Button(key_input_frame, text="🔑 Generate Keys",
                  style='Action.TButton',
                  command=self.generate_des_keys).pack(side='left')
        
        # Output frame
        output_frame = ttk.Frame(des_frame, style='Card.TFrame')
        output_frame.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        
        out_header = ttk.Frame(output_frame, style='Card.TFrame')
        out_header.pack(fill='x', padx=10, pady=(10, 5))
        ttk.Label(out_header, text="Generated Round Keys", style='Header.TLabel').pack(side='left')
        
        ttk.Button(out_header, text="💾 Save", style='Secondary.TButton',
                   command=lambda: self.save_text_to_file(self.des_output.get('1.0', 'end-1c'))).pack(side='right')
        
        self.des_output = scrolledtext.ScrolledText(output_frame, 
                                                    bg='#0a0e27', fg='#00d4ff',
                                                    font=('Consolas', 9),
                                                    relief='flat', padx=15, pady=10,
                                                    state='disabled')
        self.des_output.pack(fill='both', expand=True, padx=10, pady=(0, 10))
    
    # DES Algorithm Functions
    def left_shift(self, bits, n):
        """Perform circular left shift"""
        return bits[n:] + bits[:n]
    
    def generate_des_keys(self):
        """Generate 16 round keys for DES"""
        hex_key = self.des_key_entry.get().strip()
        
        # Validate input
        if len(hex_key) != 16 or any(c not in "0123456789abcdefABCDEF" for c in hex_key):
            messagebox.showerror("Invalid Input", 
                               "Please enter exactly 16 hexadecimal characters (0-9, A-F)!")
            return
        
        try:
            # Convert hex to binary (64-bit)
            bin_key = bin(int(hex_key, 16))[2:].zfill(64)
            
            # PC-1 Table
            PC1 = [
                57, 49, 41, 33, 25, 17, 9,
                1, 58, 50, 42, 34, 26, 18,
                10, 2, 59, 51, 43, 35, 27,
                19, 11, 3, 60, 52, 44, 36,
                63, 55, 47, 39, 31, 23, 15,
                7, 62, 54, 46, 38, 30, 22,
                14, 6, 61, 53, 45, 37, 29,
                21, 13, 5, 28, 20, 12, 4
            ]
            
            # PC-2 Table
            PC2 = [
                14, 17, 11, 24, 1, 5,
                3, 28, 15, 6, 21, 10,
                23, 19, 12, 4, 26, 8,
                16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55,
                30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32
            ]
            
            # Apply PC-1
            perm_key = "".join([bin_key[i - 1] for i in PC1])
            
            # Split into halves
            L = perm_key[:28]
            R = perm_key[28:]
            
            # Number of left shifts per round
            ROTATIONS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
            
            # Generate output text
            output_text = f"Hexadecimal Key: {hex_key}\n"
            output_text += f"Binary Key (64-bit):\n{bin_key}\n\n"
            output_text += f"After PC-1 (56-bit):\n{perm_key}\n\n"
            output_text += f"Initial L0: {L}\n"
            output_text += f"Initial R0: {R}\n\n"
            output_text += "=" * 70 + "\n"
            output_text += "16 ROUND KEYS\n"
            output_text += "=" * 70 + "\n\n"
            
            # Generate 16 subkeys
            for i in range(16):
                L = self.left_shift(L, ROTATIONS[i])
                R = self.left_shift(R, ROTATIONS[i])
                combined = L + R
                subkey = "".join([combined[j - 1] for j in PC2])
                output_text += f"Round {i+1:2d} Key: {subkey}\n"
            
            # Display output
            self.des_output.config(state='normal')
            self.des_output.delete('1.0', 'end')
            self.des_output.insert('1.0', output_text)
            self.des_output.config(state='disabled')
            
            self.set_status("DES round keys generated successfully")
            
        except Exception as ex:
            messagebox.showerror("Error", f"Key generation failed: {str(ex)}")
    
    # ==================== S-DES TAB ====================
    
    def create_sdes_tab(self):
        """Create S-DES encryption/decryption tab"""
        sdes_frame = ttk.Frame(self.notebook, style='Dark.TFrame')
        self.notebook.add(sdes_frame, text='🔒 S-DES')
        
        # Input frame
        input_frame = ttk.Frame(sdes_frame, style='Card.TFrame')
        input_frame.pack(fill='x', padx=15, pady=15)
        
        ttk.Label(input_frame, text="Simplified DES (S-DES)", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        # Key input
        key_container = ttk.Frame(input_frame, style='Card.TFrame')
        key_container.pack(fill='x', padx=10, pady=(10, 5))
        
        ttk.Label(key_container, text="10-bit Key:", style='Info.TLabel').pack(anchor='w')
        
        key_row = ttk.Frame(key_container, style='Card.TFrame')
        key_row.pack(fill='x', pady=(5, 0))
        
        self.sdes_key_entry = tk.Entry(key_row,
                                       bg='#0a0e27', fg='#0f0',
                                       font=('Consolas', 11),
                                       insertbackground='#0f0',
                                       relief='flat', width=30)
        self.sdes_key_entry.pack(side='left', padx=(0, 5), ipady=3)
        self.sdes_key_entry.insert(0, "1010000010")
        
        ttk.Button(key_row, text="📂", width=3, style='Secondary.TButton',
                   command=lambda: self.load_file_to_widget(self.sdes_key_entry)).pack(side='left', padx=5)


        
        # Plaintext input
        plain_container = ttk.Frame(input_frame, style='Card.TFrame')
        plain_container.pack(fill='x', padx=10, pady=(10, 5))
        
        ttk.Label(plain_container, text="8-bit Plaintext:", style='Info.TLabel').pack(anchor='w')
        
        plain_row = ttk.Frame(plain_container, style='Card.TFrame')
        plain_row.pack(fill='x', pady=(5, 0))
        
        self.sdes_plain_entry = tk.Entry(plain_row,
                                         bg='#0a0e27', fg='#0f0',
                                         font=('Consolas', 11),
                                         insertbackground='#0f0',
                                         relief='flat', width=30)
        self.sdes_plain_entry.pack(side='left', padx=(0, 5), ipady=3)
        self.sdes_plain_entry.insert(0, "10100010")
        
        ttk.Button(plain_row, text="📂", width=3, style='Secondary.TButton',
                   command=lambda: self.load_file_to_widget(self.sdes_plain_entry)).pack(side='left', padx=5)
        
        # Generated keys display
        subkeys_container = ttk.Frame(input_frame, style='Card.TFrame')
        subkeys_container.pack(fill='x', padx=10, pady=(10, 5))
        
        ttk.Label(subkeys_container, text="Generated Subkeys:", style='Info.TLabel').pack(anchor='w')
        
        subkeys_row = ttk.Frame(subkeys_container, style='Card.TFrame')
        subkeys_row.pack(fill='x', pady=(5, 10))
        
        self.sdes_subkeys = tk.Text(subkeys_row, height=2, width=40,
                                    bg='#0a0e27', fg='#00d4ff',
                                    font=('Consolas', 9),
                                    relief='flat', padx=5, pady=5,
                                    state='disabled')
        self.sdes_subkeys.pack(side='left', padx=(0, 10))
        
        ttk.Button(subkeys_row, text="🔑 Generate Subkeys",
                   style='Action.TButton',
                   command=self.sdes_generate_keys).pack(side='left')
        

        
        # Output frame
        output_frame = ttk.Frame(sdes_frame, style='Card.TFrame')
        output_frame.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        
        ttk.Label(output_frame, text="Results", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        # Ciphertext
        result_container = ttk.Frame(output_frame, style='Card.TFrame')
        result_container.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(result_container, text="Ciphertext:", style='Info.TLabel').pack(side='left', padx=(0, 10))
        self.sdes_cipher_label = tk.Label(result_container,
                                         bg='#0a0e27', fg='#ff6b6b',
                                         font=('Consolas', 12, 'bold'),
                                         width=15, anchor='w',
                                         padx=10, pady=5)
        self.sdes_cipher_label.pack(side='left', fill='x', expand=True)
        
        ttk.Button(result_container, text="📋",
                  style='Secondary.TButton',
                  command=lambda: self.copy_text(self.sdes_cipher_label.cget('text'))).pack(side='left', padx=5)

        ttk.Button(result_container, text="💾",
                  style='Secondary.TButton',
                  command=lambda: self.save_text_to_file(self.sdes_cipher_label.cget('text'))).pack(side='left', padx=5)
        
        # Decrypted text
        decrypt_container = ttk.Frame(output_frame, style='Card.TFrame')
        decrypt_container.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(decrypt_container, text="Decrypted:", style='Info.TLabel').pack(side='left', padx=(0, 10))
        self.sdes_decrypt_label = tk.Label(decrypt_container,
                                          bg='#0a0e27', fg='#0f0',
                                          font=('Consolas', 12, 'bold'),
                                          width=15, anchor='w',
                                          padx=10, pady=5)
        self.sdes_decrypt_label.pack(side='left', fill='x', expand=True)
        
        ttk.Button(decrypt_container, text="📋",
                  style='Secondary.TButton',
                  command=lambda: self.copy_text(self.sdes_decrypt_label.cget('text'))).pack(side='left', padx=5)

        ttk.Button(decrypt_container, text="💾",
                  style='Secondary.TButton',
                  command=lambda: self.save_text_to_file(self.sdes_decrypt_label.cget('text'))).pack(side='left', padx=5)
        
        # Action buttons
        action_frame = ttk.Frame(output_frame, style='Card.TFrame')
        action_frame.pack(pady=15)
        
        ttk.Button(action_frame, text="🔒 ENCRYPT",
                  style='Action.TButton',
                  command=self.sdes_encrypt).pack(side='left', padx=5)
        
        ttk.Button(action_frame, text="🔓 DECRYPT",
                  style='Action.TButton',
                  command=self.sdes_decrypt).pack(side='left', padx=5)
    
    # S-DES Algorithm Functions
    def sdes_permute(self, bits, pattern):
        """Rearrange bits according to a pattern"""
        return ''.join(bits[i - 1] for i in pattern)
    
    def sdes_key_generation(self, key):
        """Generate K1 and K2 for S-DES"""
        P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
        P8 = [6, 3, 7, 4, 8, 5, 10, 9]
        
        key = self.sdes_permute(key, P10)
        left, right = key[:5], key[5:]
        
        # Left shift by 1
        left = self.left_shift(left, 1)
        right = self.left_shift(right, 1)
        K1 = self.sdes_permute(left + right, P8)
        
        # Left shift by 2 more
        left = self.left_shift(left, 2)
        right = self.left_shift(right, 2)
        K2 = self.sdes_permute(left + right, P8)
        
        return K1, K2
    
    def sdes_fk(self, bits, key):
        """S-DES fk function"""
        EP = [4, 1, 2, 3, 2, 3, 4, 1]
        S0 = [
            [1, 0, 3, 2],
            [3, 2, 1, 0],
            [0, 2, 1, 3],
            [3, 1, 3, 2]
        ]
        S1 = [
            [0, 1, 2, 3],
            [2, 0, 1, 3],
            [3, 0, 1, 0],
            [2, 1, 0, 3]
        ]
        
        left, right = bits[:4], bits[4:]
        
        # Expand and permute
        right_expanded = self.sdes_permute(right, EP)
        
        # XOR with key
        xor_result = ''.join(str(int(a) ^ int(b)) for a, b in zip(right_expanded, key))
        
        # Split for S-boxes
        left_xor, right_xor = xor_result[:4], xor_result[4:]
        
        # S-box lookup
        def sbox_lookup(bits, sbox):
            row = int(bits[0] + bits[3], 2)
            col = int(bits[1] + bits[2], 2)
            return format(sbox[row][col], '02b')
        
        sbox_output = sbox_lookup(left_xor, S0) + sbox_lookup(right_xor, S1)
        
        # XOR with left half and right half
        left_result = ''.join(str(int(a) ^ int(b) ^ int(c)) for a, b, c in zip(left, sbox_output, right))
        
        return left_result + right
    
    def sdes_encrypt_text(self, plaintext, key):
        """Encrypt using S-DES"""
        IP = [2, 6, 3, 1, 4, 8, 5, 7]
        IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]
        
        K1, K2 = self.sdes_key_generation(key)
        
        bits = self.sdes_permute(plaintext, IP)
        bits = self.sdes_fk(bits, K1)
        bits = bits[4:] + bits[:4]  # Swap halves
        bits = self.sdes_fk(bits, K2)
        ciphertext = self.sdes_permute(bits, IP_inv)
        
        return ciphertext
    
    def sdes_decrypt_text(self, ciphertext, key):
        """Decrypt using S-DES"""
        IP = [2, 6, 3, 1, 4, 8, 5, 7]
        IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]
        
        K1, K2 = self.sdes_key_generation(key)
        
        bits = self.sdes_permute(ciphertext, IP)
        bits = self.sdes_fk(bits, K2)
        bits = bits[4:] + bits[:4]  # Swap halves
        bits = self.sdes_fk(bits, K1)
        plaintext = self.sdes_permute(bits, IP_inv)
        
        return plaintext
    
    def sdes_generate_keys(self):
        """Generate and display S-DES subkeys"""
        key = self.sdes_key_entry.get().strip()
        
        if len(key) != 10 or any(c not in '01' for c in key):
            messagebox.showerror("Invalid Input", "Please enter exactly 10 binary digits (0 or 1)!")
            return
        
        try:
            K1, K2 = self.sdes_key_generation(key)
            
            self.sdes_subkeys.config(state='normal')
            self.sdes_subkeys.delete('1.0', 'end')
            self.sdes_subkeys.insert('1.0', f"K1: {K1}\nK2: {K2}")
            self.sdes_subkeys.config(state='disabled')
            
            self.set_status("S-DES subkeys generated")
        except Exception as ex:
            messagebox.showerror("Error", f"Key generation failed: {str(ex)}")
    
    def sdes_encrypt(self):
        """Encrypt plaintext using S-DES"""
        key = self.sdes_key_entry.get().strip()
        plaintext = self.sdes_plain_entry.get().strip()
        
        if len(key) != 10 or any(c not in '01' for c in key):
            messagebox.showerror("Invalid Input", "Key must be 10 binary digits!")
            return
        
        if len(plaintext) != 8 or any(c not in '01' for c in plaintext):
            messagebox.showerror("Invalid Input", "Plaintext must be 8 binary digits!")
            return
        
        try:
            ciphertext = self.sdes_encrypt_text(plaintext, key)
            self.sdes_cipher_label.config(text=ciphertext)
            self.sdes_decrypt_label.config(text="")
            self.set_status("S-DES encryption successful")
        except Exception as ex:
            messagebox.showerror("Error", f"Encryption failed: {str(ex)}")
    
    def sdes_decrypt(self):
        """Decrypt ciphertext using S-DES"""
        key = self.sdes_key_entry.get().strip()
        ciphertext = self.sdes_cipher_label.cget('text').strip()
        
        if not ciphertext:
            messagebox.showwarning("No Ciphertext", "Please encrypt a message first!")
            return
        
        if len(key) != 10 or any(c not in '01' for c in key):
            messagebox.showerror("Invalid Input", "Key must be 10 binary digits!")
            return
        
        try:
            plaintext = self.sdes_decrypt_text(ciphertext, key)
            self.sdes_decrypt_label.config(text=plaintext)
            self.set_status("S-DES decryption successful")
        except Exception as ex:
            messagebox.showerror("Error", f"Decryption failed: {str(ex)}")
    
    # ==================== MD5 FIRST ROUND TAB ====================
    
    def create_md5_tab(self):
        """Create MD5 First Round visualization tab"""
        md5_frame = ttk.Frame(self.notebook, style='Dark.TFrame')
        self.notebook.add(md5_frame, text='🛡️ MD5')
        
        # Input frame
        input_frame = ttk.Frame(md5_frame, style='Card.TFrame')
        input_frame.pack(fill='x', padx=15, pady=15)
        
        ttk.Label(input_frame, text="MD5 First Round Visualization", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        ttk.Label(input_frame, text="Enter Text to Hash:", style='Info.TLabel').pack(anchor='w', padx=10, pady=(5, 5))
        
        input_container = ttk.Frame(input_frame, style='Card.TFrame')
        input_container.pack(fill='x', padx=10, pady=(0, 10))
        
        self.md5_entry = tk.Entry(input_container, 
                                bg='#0a0e27', fg='#0f0',
                                font=('Consolas', 11),
                                insertbackground='#0f0',
                                relief='flat', width=40)
        self.md5_entry.pack(side='left', padx=(0, 10), pady=5, ipady=5, fill='x', expand=True)
        self.md5_entry.insert(0, "security")
        
        ttk.Button(input_container, text="📂", width=3,
                  style='Secondary.TButton',
                  command=lambda: self.load_file_to_widget(self.md5_entry)).pack(side='left', padx=(0, 5))
        
        ttk.Button(input_container, text="⚡ Run Round 1",
                  style='Action.TButton',
                  command=self.run_md5_round1).pack(side='left')

        # Info Frame
        self.md5_info_label = tk.Label(input_frame, text="", 
                                     bg='#16213e', fg='#00d4ff',
                                     font=('Consolas', 9), justify='left')
        self.md5_info_label.pack(anchor='w', padx=10, pady=(0, 10))
        
        # Log Output frame
        output_frame = ttk.Frame(md5_frame, style='Card.TFrame')
        output_frame.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        
        out_header = ttk.Frame(output_frame, style='Card.TFrame')
        out_header.pack(fill='x', padx=10, pady=(10, 5))
        ttk.Label(out_header, text="Round 1 Steps Log (16 Operations)", style='Header.TLabel').pack(side='left')
        
        ttk.Button(out_header, text="💾 Save Log", style='Secondary.TButton',
                   command=lambda: self.save_text_to_file(self.md5_log.get('1.0', 'end-1c'))).pack(side='right')
        
        self.md5_log = scrolledtext.ScrolledText(output_frame, 
                                                bg='#0a0e27', fg='#0f0',
                                                font=('Consolas', 9),
                                                relief='flat', padx=15, pady=10,
                                                state='disabled')
        self.md5_log.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
    def run_md5_round1(self):
        """Execute MD5 First Round logic"""
        text = self.md5_entry.get()
        if not text:
            messagebox.showwarning("Input Error", "Please enter text to hash!")
            return
            
        try:
            # 1. Padding Logic (from provided code)
            msg_bytes = bytearray(text.encode('utf-8'))
            msg_len_bits = len(msg_bytes) * 8
            import math
            blocks = math.floor(msg_len_bits / 512)
            len_block = msg_len_bits - (blocks * 512)
            if len_block < 448:
                pad_len = 512 - (len_block + 64)
            else:
                pad_len = (512 - (len_block + 64)) + 512
            
            total_len_bits = msg_len_bits + pad_len + 64
            
            info_text = (f"Original Length: {len(text)} chars ({msg_len_bits} bits)\n"
                         f"Padding Added:   {pad_len} bits\n"
                         f"Total Length:    {total_len_bits} bits (Multiple of 512)")
            self.md5_info_label.config(text=info_text)
            
            # 2. Initialize State
            a = 0x67452301
            b = 0xefcdab89
            c = 0x98badcfe
            d = 0x10325476
            
            # Constants
            s1 = [7, 12, 17, 22]
            t = [
                0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821
            ]
            
            log_text = f"Initial State:\n  A: {a:08x}\n  B: {b:08x}\n  C: {c:08x}\n  D: {d:08x}\n\n"
            log_text += "=" * 60 + "\n"
            
            # 3. Simulate Round 1 (16 operations)
            # In a real MD5, we'd process 512-bit blocks. Here we simulate the first block's first round.
            # We need 'M' (message block). For demo, strictly padding isn't fully constructed in the user code, 
            # so we'll mock the M[0]...M[15] as part of the visualizer or just use 0 if not enough data, 
            # but to be accurate we should construct the block.
            
            # Construct the padded block (simplified for demonstration of Round 1 on the first block)
            # Append '1' bit (0x80 byte)
            msg_bytes.append(0x80)
            while (len(msg_bytes) * 8) % 512 != 448:
                msg_bytes.append(0)
            
            # Append length (64 bits, little endian)
            msg_bytes += (msg_len_bits).to_bytes(8, byteorder='little')
            
            # Extract first 16 words (32-bit blocks)
            M = []
            for i in range(16):
                val = int.from_bytes(msg_bytes[i*4:(i+1)*4], byteorder='little')
                M.append(val)
                
            # Round 1 Loop
            for i in range(16):
                # Save old state for display (optional, but we show result after)
                
                # F function
                f = (b & c) | (~b & d)
                
                # Operation: a = b + ((a + F(b,c,d) + M[k] + T[i]) <<< s)
                temp = (a + f + M[i] + t[i]) & 0xFFFFFFFF
                shift = s1[i % 4]
                rotated = ((temp << shift) | (temp >> (32 - shift))) & 0xFFFFFFFF
                new_b = (b + rotated) & 0xFFFFFFFF
                
                # Rotate variables
                a, b, c, d = d, new_b, b, c
                
                log_text += f"Step {i+1:02d}:\n"
                log_text += f"  Function F result: {f:08x}\n"
                log_text += f"  M[{i}]:            {M[i]:08x}\n"
                log_text += f"  Shift:            {shift}\n"
                log_text += f"  New State -> A:{a:08x} B:{b:08x} C:{c:08x} D:{d:08x}\n"
                log_text += "-" * 40 + "\n"
                
            self.md5_log.config(state='normal')
            self.md5_log.delete('1.0', 'end')
            self.md5_log.insert('1.0', log_text)
            self.md5_log.config(state='disabled')
            
            self.set_status("MD5 Round 1 simulated successfully")

        except Exception as ex:
            messagebox.showerror("Error", f"MD5 execution failed: {str(ex)}")

    # ==================== SHA-1 TAB ====================
    
    def create_sha1_tab(self):
        """Create SHA-1 Hash tab"""
        sha1_frame = ttk.Frame(self.notebook, style='Dark.TFrame')
        self.notebook.add(sha1_frame, text='🛡️ SHA-1')
        
        # Input frame
        input_frame = ttk.Frame(sha1_frame, style='Card.TFrame')
        input_frame.pack(fill='x', padx=15, pady=15)
        
        ttk.Label(input_frame, text="SHA-1 Secure Hash Algorithm", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        ttk.Label(input_frame, text="Enter Text to Hash:", style='Info.TLabel').pack(anchor='w', padx=10, pady=(5, 5))
        
        input_container = ttk.Frame(input_frame, style='Card.TFrame')
        input_container.pack(fill='x', padx=10, pady=(0, 10))
        
        self.sha1_entry = tk.Entry(input_container, 
                                 bg='#0a0e27', fg='#0f0',
                                 font=('Consolas', 11),
                                 insertbackground='#0f0',
                                 relief='flat', width=40)
        self.sha1_entry.pack(side='left', padx=(0, 10), pady=5, ipady=5, fill='x', expand=True)

        ttk.Button(input_container, text="📂", width=3,
                  style='Secondary.TButton',
                  command=lambda: self.load_file_to_widget(self.sha1_entry)).pack(side='left', padx=(0, 5))
        
        ttk.Button(input_container, text="⚡ Calculate Hash",
                  style='Action.TButton',
                  command=self.run_sha1).pack(side='left')

        # Output frame
        output_frame = ttk.Frame(sha1_frame, style='Card.TFrame')
        output_frame.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        
        ttk.Label(output_frame, text="SHA-1 Digest (160-bit)", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        result_container = ttk.Frame(output_frame, style='Card.TFrame')
        result_container.pack(fill='x', padx=10, pady=(0, 10))
        
        self.sha1_result = tk.Label(result_container,
                                  bg='#0a0e27', fg='#00d4ff',
                                  font=('Consolas', 12, 'bold'),
                                  anchor='w', padx=10, pady=10)
        self.sha1_result.pack(side='left', fill='x', expand=True)
        
        ttk.Button(result_container, text="📋",
                  style='Secondary.TButton',
                  command=lambda: self.copy_text(self.sha1_result.cget('text'))).pack(side='left', padx=5)

        ttk.Button(result_container, text="💾",
                  style='Secondary.TButton',
                  command=lambda: self.save_text_to_file(self.sha1_result.cget('text'))).pack(side='left', padx=5)

    def left_rotate(self, n, b):
        """Left rotate n by b bits."""
        return ((n << b) | (n >> (32 - b))) & 0xffffffff

    def sha1_hash(self, message):
        """Implementation of SHA-1 algorithm"""
        # Step 1: Convert message to bytes
        if isinstance(message, str):
            data = bytearray(message, 'utf-8')
        else:
            data = bytearray(message)
        
        orig_len_bits = len(data) * 8
        
        # Step 2: Append padding
        data.append(0x80)
        while (len(data) * 8) % 512 != 448:
            data.append(0x00)
        
        # Step 3: Append original length (64 bits, big-endian)
        data += struct.pack('>Q', orig_len_bits)
        
        # Step 4: Initialize buffers
        h0 = 0x67452301
        h1 = 0xEFCDAB89
        h2 = 0x98BADCFE
        h3 = 0x10325476
        h4 = 0xC3D2E1F0
        
        # Step 5: Process each 512-bit block
        for i in range(0, len(data), 64):
            chunk = data[i:i+64]
            words = list(struct.unpack('>16I', chunk))
            
            for j in range(16, 80):
                word = (words[j-3] ^ words[j-8] ^ words[j-14] ^ words[j-16])
                words.append(self.left_rotate(word, 1))
            
            a, b, c, d, e = h0, h1, h2, h3, h4
            
            for j in range(80):
                if 0 <= j <= 19:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                elif 20 <= j <= 39:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif 40 <= j <= 59:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                else:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6
                
                temp = (self.left_rotate(a, 5) + f + e + k + words[j]) & 0xffffffff
                e = d
                d = c
                c = self.left_rotate(b, 30)
                b = a
                a = temp
            
            h0 = (h0 + a) & 0xffffffff
            h1 = (h1 + b) & 0xffffffff
            h2 = (h2 + c) & 0xffffffff
            h3 = (h3 + d) & 0xffffffff
            h4 = (h4 + e) & 0xffffffff
        
        return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)

    def run_sha1(self):
        """Execute SHA-1 hashing"""
        text = self.sha1_entry.get()
        if not text:
            messagebox.showwarning("Input Error", "Please enter text to hash!")
            return
        try:
            hashed = self.sha1_hash(text)
            self.sha1_result.config(text=hashed)
            self.set_status("SHA-1 Hash calculated successfully")
        except Exception as ex:
            messagebox.showerror("Error", f"SHA-1 execution failed: {str(ex)}")

    # ==================== FULL MD5 TAB ====================

    def create_full_md5_tab(self):
        """Create Full MD5 Hash tab"""
        md5_frame = ttk.Frame(self.notebook, style='Dark.TFrame')
        self.notebook.add(md5_frame, text='🛡️ Full MD5')
        
        # Input frame
        input_frame = ttk.Frame(md5_frame, style='Card.TFrame')
        input_frame.pack(fill='x', padx=15, pady=15)
        
        ttk.Label(input_frame, text="MD5 Message Digest Algorithm (Full)", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        ttk.Label(input_frame, text="Enter Text to Hash:", style='Info.TLabel').pack(anchor='w', padx=10, pady=(5, 5))
        
        input_container = ttk.Frame(input_frame, style='Card.TFrame')
        input_container.pack(fill='x', padx=10, pady=(0, 10))
        
        self.full_md5_entry = tk.Entry(input_container, 
                                     bg='#0a0e27', fg='#0f0',
                                     font=('Consolas', 11),
                                     insertbackground='#0f0',
                                     relief='flat', width=40)
        self.full_md5_entry.pack(side='left', padx=(0, 10), pady=5, ipady=5, fill='x', expand=True)

        ttk.Button(input_container, text="📂", width=3,
                  style='Secondary.TButton',
                  command=lambda: self.load_file_to_widget(self.full_md5_entry)).pack(side='left', padx=(0, 5))
        
        ttk.Button(input_container, text="⚡ Calculate Hash",
                  style='Action.TButton',
                  command=self.run_full_md5).pack(side='left')

        # Output frame
        output_frame = ttk.Frame(md5_frame, style='Card.TFrame')
        output_frame.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        
        ttk.Label(output_frame, text="MD5 Digest (128-bit)", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        result_container = ttk.Frame(output_frame, style='Card.TFrame')
        result_container.pack(fill='x', padx=10, pady=(0, 10))
        
        self.full_md5_result = tk.Label(result_container,
                                      bg='#0a0e27', fg='#00d4ff',
                                      font=('Consolas', 12, 'bold'),
                                      anchor='w', padx=10, pady=10)
        self.full_md5_result.pack(side='left', fill='x', expand=True)
        
        ttk.Button(result_container, text="📋",
                  style='Secondary.TButton',
                  command=lambda: self.copy_text(self.full_md5_result.cget('text'))).pack(side='left', padx=5)
        
        ttk.Button(result_container, text="💾",
                  style='Secondary.TButton',
                  command=lambda: self.save_text_to_file(self.full_md5_result.cget('text'))).pack(side='left', padx=5)

        # Log Notebook (Nested)
        log_frame = ttk.Frame(md5_frame, style='Card.TFrame')
        log_frame.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        
        ttk.Label(log_frame, text="Detailed Operation Logs (64 Steps)", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        self.md5_log_notebook = ttk.Notebook(log_frame)
        self.md5_log_notebook.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
        self.md5_round_logs = []
        for i in range(4):
            round_frame = ttk.Frame(self.md5_log_notebook, style='Dark.TFrame')
            self.md5_log_notebook.add(round_frame, text=f'Round {i+1}')
            
            log_text = scrolledtext.ScrolledText(round_frame, bg='#0a0e27', fg='#0f0', font=('Consolas', 9), state='disabled', relief='flat')
            log_text.pack(fill='both', expand=True, padx=5, pady=5)
            self.md5_round_logs.append(log_text)

    def full_md5_hash(self, message):
        """Implementation of Full MD5 algorithm with logging"""
        msg_bytes = bytearray(message.encode('utf-8'))
        orig_len_bits = len(msg_bytes) * 8
        msg_bytes.append(0x80)
        while (len(msg_bytes) * 8) % 512 != 448:
            msg_bytes.append(0x00)
        
        msg_bytes += struct.pack('<Q', orig_len_bits)
        
        a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
        
        s = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
             5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
             4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
             6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]
        
        K = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
             0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
             0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
             0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
             0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
             0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
             0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
             0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391]
        
        logs = [[], [], [], []] # 4 Rounds
        
        for i in range(0, len(msg_bytes), 64):
            block = msg_bytes[i:i+64]
            M = list(struct.unpack('<16I', block))
            A, B, C, D = a0, b0, c0, d0
            
            for j in range(64):
                if 0 <= j <= 15:
                    F = (B & C) | ((~B) & D)
                    g = j
                    round_idx = 0
                elif 16 <= j <= 31:
                    F = (D & B) | ((~D) & C)
                    g = (5*j + 1) % 16
                    round_idx = 1
                elif 32 <= j <= 47:
                    F = B ^ C ^ D
                    g = (3*j + 5) % 16
                    round_idx = 2
                else:
                    F = C ^ (B | (~D))
                    g = (7*j) % 16
                    round_idx = 3
                
                # Log state before op
                log_entry = f"Step {j:02d} | M[{g:2d}] | "
                
                F = (F + A + K[j] + M[g]) & 0xFFFFFFFF
                A, D, C, B = D, C, B, (B + self.left_rotate(F, s[j])) & 0xFFFFFFFF
                
                # Log state after op
                log_entry += f"A={A:08x} B={B:08x} C={C:08x} D={D:08x}\n"
                logs[round_idx].append(log_entry)
            
            a0 = (a0 + A) & 0xFFFFFFFF
            b0 = (b0 + B) & 0xFFFFFFFF
            c0 = (c0 + C) & 0xFFFFFFFF
            d0 = (d0 + D) & 0xFFFFFFFF
            
        digest = struct.pack('<4I', a0, b0, c0, d0).hex()
        return digest, logs

    def run_full_md5(self):
        """Execute Full MD5 hashing with logs"""
        text = self.full_md5_entry.get()
        if not text:
            messagebox.showwarning("Input Error", "Please enter text to hash!")
            return
        try:
            hashed, logs = self.full_md5_hash(text)
            self.full_md5_result.config(text=hashed)
            
            # Update Logs
            for i in range(4):
                self.md5_round_logs[i].config(state='normal')
                self.md5_round_logs[i].delete('1.0', 'end')
                self.md5_round_logs[i].insert('1.0', "".join(logs[i]) if logs[i] else "No data for this round (short message?)")
                self.md5_round_logs[i].config(state='disabled')
                
            self.set_status("Full MD5 Hash calculated successfully")
        except Exception as ex:
            messagebox.showerror("Error", f"Full MD5 execution failed: {str(ex)}")

    def create_jwt_tab(self):
        """Create JWT Create and Verify tab"""
        jwt_frame = ttk.Frame(self.notebook, style='Dark.TFrame')
        self.notebook.add(jwt_frame, text='🎟 JWT')
        
        # Split into two columns: Create and Verify
        paned = ttk.PanedWindow(jwt_frame, orient='horizontal')
        paned.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Left Side: JWT Create
        create_frame = ttk.Frame(paned, style='Dark.TFrame')
        paned.add(create_frame, weight=1)
        
        ttk.Label(create_frame, text="Generate Token", style='Title.TLabel').pack(anchor='center', pady=(0, 10))
        
        # Inputs for Create
        input_container = ttk.Frame(create_frame, style='Card.TFrame')
        input_container.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(input_container, text="Payload Data", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        fields_frame = ttk.Frame(input_container, style='Card.TFrame')
        fields_frame.pack(fill='x', padx=10, pady=5)
        
        # ID Field
        ttk.Label(fields_frame, text="ID:", style='Info.TLabel').grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.jwt_id_ent = ttk.Entry(fields_frame, font=('Consolas', 10))
        self.jwt_id_ent.grid(row=0, column=1, sticky='ew', padx=5, pady=5)
        
        # Name Field
        ttk.Label(fields_frame, text="Name:", style='Info.TLabel').grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.jwt_name_ent = ttk.Entry(fields_frame, font=('Consolas', 10))
        self.jwt_name_ent.grid(row=1, column=1, sticky='ew', padx=5, pady=5)
        
        # Email Field
        ttk.Label(fields_frame, text="Email:", style='Info.TLabel').grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.jwt_email_ent = ttk.Entry(fields_frame, font=('Consolas', 10))
        self.jwt_email_ent.grid(row=2, column=1, sticky='ew', padx=5, pady=5)
        
        fields_frame.columnconfigure(1, weight=1)
        
        # Secret Key Input for Create
        secret_frame = ttk.Frame(create_frame, style='Card.TFrame')
        secret_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(secret_frame, text="Signing Secret Key", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        self.jwt_create_secret_ent = ttk.Entry(secret_frame, font=('Consolas', 10), show='*')
        self.jwt_create_secret_ent.pack(fill='x', padx=10, pady=(0, 10))
        
        # Generate Button
        ttk.Button(create_frame, text="⚡ Generate JWT", style='Action.TButton',
                   command=self.generate_jwt).pack(pady=10)
        
        # Generated Token Output
        ttk.Label(create_frame, text="Generated Token", style='Header.TLabel').pack(anchor='w', padx=10)
        self.jwt_gen_token = scrolledtext.ScrolledText(create_frame, height=5, bg='#0a0e27', fg='#0f0',
                                                       font=('Consolas', 10), relief='flat')
        self.jwt_gen_token.pack(fill='x', padx=10, pady=(0, 10))
        
        # Right Side: JWT Verify
        verify_frame = ttk.Frame(paned, style='Dark.TFrame')
        paned.add(verify_frame, weight=1)
        
        ttk.Label(verify_frame, text="Verify Token", style='Title.TLabel').pack(anchor='center', pady=(0, 10))
        
        # Token Input
        verify_input_frame = ttk.Frame(verify_frame, style='Card.TFrame')
        verify_input_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(verify_input_frame, text="Token to Verify", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        self.jwt_verify_token_ent = scrolledtext.ScrolledText(verify_input_frame, height=5, bg='#0a0e27', fg='#00d4ff',
                                                              font=('Consolas', 10), relief='flat')
        self.jwt_verify_token_ent.pack(fill='x', padx=10, pady=(0, 10))
        
        # Secret Key Input for Verify
        verify_secret_frame = ttk.Frame(verify_frame, style='Card.TFrame')
        verify_secret_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(verify_secret_frame, text="Verification Secret Key", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        self.jwt_verify_secret_ent = ttk.Entry(verify_secret_frame, font=('Consolas', 10), show='*')
        self.jwt_verify_secret_ent.pack(fill='x', padx=10, pady=(0, 10))
        
        # Verify Button
        ttk.Button(verify_frame, text="🔍 Verify JWT", style='Action.TButton',
                   command=self.verify_jwt).pack(pady=10)
        
        # Verification Result
        ttk.Label(verify_frame, text="Verification Result", style='Header.TLabel').pack(anchor='w', padx=10)
        self.jwt_result_area = scrolledtext.ScrolledText(verify_frame, height=8, bg='#0a0e27', fg='#fff',
                                                         font=('Consolas', 10), relief='flat', state='disabled')
        self.jwt_result_area.pack(fill='both', expand=True, padx=10, pady=(0, 10))

    def generate_jwt(self):
        user_id = self.jwt_id_ent.get().strip()
        name = self.jwt_name_ent.get().strip()
        email = self.jwt_email_ent.get().strip()
        secret = self.jwt_create_secret_ent.get().strip()
        
        if not user_id or not name or not email or not secret:
            messagebox.showwarning("Missing Data", "Please fill in all fields (ID, Name, Email, Secret).")
            return
            
        payload = {
            "id": user_id,
            "name": name,
            "email": email,
            "iat": datetime.datetime.utcnow(),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
        }
        
        try:
            token = jwt.encode(payload, secret, algorithm="HS256")
            
            # Show in generated area
            self.jwt_gen_token.delete('1.0', 'end')
            self.jwt_gen_token.insert('1.0', token)
            
            # Auto-fill verify section
            self.jwt_verify_token_ent.delete('1.0', 'end')
            self.jwt_verify_token_ent.insert('1.0', token)
            
            self.set_status("JWT Generated and copied to Verifier")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate JWT: {str(e)}")

    def verify_jwt(self):
        token = self.jwt_verify_token_ent.get('1.0', 'end-1c').strip()
        secret = self.jwt_verify_secret_ent.get().strip()
        
        if not token or not secret:
            messagebox.showwarning("Missing Data", "Please provide both Token and Verification Secret.")
            return
            
        self.jwt_result_area.config(state='normal')
        self.jwt_result_area.delete('1.0', 'end')
        
        try:
            decoded_data = jwt.decode(token, secret, algorithms=["HS256"])
            
            result_text = "✅ Signature is VALID!\n\n"
            result_text += "Decoded Payload:\n"
            result_text += "-------------------\n"
            for k, v in decoded_data.items():
                result_text += f"{k:10}: {v}\n"
                
            self.jwt_result_area.insert('1.0', result_text)
            self.jwt_result_area.config(fg='#0f0') # Green for success
            self.set_status("JWT Verification Successful")
            
        except jwt.ExpiredSignatureError:
            self.jwt_result_area.insert('1.0', "❌ Token has EXPIRED!")
            self.jwt_result_area.config(fg='#ff6b6b')
            self.set_status("JWT Expired")
            
        except jwt.InvalidSignatureError:
            self.jwt_result_area.insert('1.0', "❌ WRONG Signature! Verification Failed.")
            self.jwt_result_area.config(fg='#ff6b6b')
            self.set_status("JWT Signature Mismatch")
            
        except jwt.InvalidTokenError:
            self.jwt_result_area.insert('1.0', "❌ Invalid Token Format.")
            self.jwt_result_area.config(fg='#ff6b6b')
            self.set_status("Invalid JWT")
            
        except Exception as e:
            self.jwt_result_area.insert('1.0', f"❌ Error: {str(e)}")
            self.jwt_result_area.config(fg='#ff6b6b')
            
        self.jwt_result_area.config(state='disabled')
    
    def create_dss_tab(self):
        """Create Digital Signature Standard (DSS) tab"""
        dss_frame = ttk.Frame(self.notebook, style='Dark.TFrame')
        self.notebook.add(dss_frame, text='✍️ DSS')
        
        # Parameters frame
        param_frame = ttk.Frame(dss_frame, style='Card.TFrame')
        param_frame.pack(fill='x', padx=15, pady=15)
        
        ttk.Label(param_frame, text="DSS Parameters (Educational)", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        self.dss_p = 23
        self.dss_q = 11
        self.dss_g = 4
        
        info = f"Public Parameters:\nPrime Modulus (p) = {self.dss_p}\nPrime Divisor (q) = {self.dss_q}\nGenerator (g) = {self.dss_g}"
        ttk.Label(param_frame, text=info, style='Info.TLabel', justify='left').pack(anchor='w', padx=10, pady=(0, 10))
        
        # Key Generation
        key_frame = ttk.Frame(dss_frame, style='Card.TFrame')
        key_frame.pack(fill='x', padx=15, pady=(0, 15))
        
        ttk.Label(key_frame, text="Key Generation", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        btn_frame = ttk.Frame(key_frame, style='Dark.TFrame')
        btn_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(btn_frame, text="🔑 Generate Keys", 
                  style='Action.TButton',
                  command=self.generate_dss_keys).pack(side='left')
                  
        self.dss_keys_label = ttk.Label(key_frame, text="Keys not generated", style='Info.TLabel')
        self.dss_keys_label.pack(anchor='w', padx=10, pady=(5, 10))
        
        # Signing & Verification
        action_frame = ttk.Frame(dss_frame, style='Card.TFrame')
        action_frame.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        
        ttk.Label(action_frame, text="Sign & Verify", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        # Message input
        # Message input
        msg_header = ttk.Frame(action_frame, style='Card.TFrame')
        msg_header.pack(fill='x', padx=10)
        
        ttk.Label(msg_header, text="Message:", style='Info.TLabel').pack(side='left')
        ttk.Button(msg_header, text="📂 Load File", 
                  style='Secondary.TButton',
                  command=lambda: self.load_file_to_widget(self.dss_msg_entry)).pack(side='right')

        self.dss_msg_entry = tk.Entry(action_frame, bg='#0a0e27', fg='#0f0', font=('Consolas', 11), insertbackground='#0f0', relief='flat')
        self.dss_msg_entry.pack(fill='x', padx=10, pady=5)
        
        # Determine Signature
        sig_btn_frame = ttk.Frame(action_frame, style='Dark.TFrame')
        sig_btn_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(sig_btn_frame, text="✍️ Sign Message", 
                  style='Action.TButton',
                  command=self.dss_sign).pack(side='left', padx=(0, 10))
                  
        self.dss_sig_label = ttk.Label(action_frame, text="Signature: None", style='Info.TLabel')
        self.dss_sig_label.pack(side='left', padx=10)
        
        ttk.Button(sig_btn_frame, text="💾",
                  style='Secondary.TButton',
                  command=lambda: self.save_text_to_file(self.dss_sig_label.cget('text'))).pack(side='left', padx=5)
        
        # Verification
        verify_btn_frame = ttk.Frame(action_frame, style='Dark.TFrame')
        verify_btn_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(verify_btn_frame, text="✓ Verify Signature", 
                  style='Secondary.TButton',
                  command=self.dss_verify).pack(side='left', padx=(0, 10))
                  
        self.dss_verify_label = ttk.Label(action_frame, text="", style='Info.TLabel')
        self.dss_verify_label.pack(anchor='w', padx=10, pady=5)

    def simple_hash(self, message):
        """Simplified hash function for DSS demo"""
        hash_val = 0
        for char in message:
            hash_val += ord(char)
        return hash_val % self.dss_q

    def generate_dss_keys(self):
        """Generate DSS keys"""
        try:
            # Private key x: random between 1 and q-1
            self.dss_x = random.randint(1, self.dss_q - 1)
            # Public key y: g^x mod p
            self.dss_y = pow(self.dss_g, self.dss_x, self.dss_p)
            
            self.dss_keys_label.config(text=f"Private Key (x): {self.dss_x}\nPublic Key (y): {self.dss_y}")
            self.set_status("DSS Keys Generated")
        except Exception as ex:
            messagebox.showerror("Error", f"Key Gen Error: {str(ex)}")

    def dss_sign(self):
        """Sign message using DSS"""
        if not hasattr(self, 'dss_x'):
            messagebox.showwarning("Error", "Generate keys first!")
            return
            
        message = self.dss_msg_entry.get()
        if not message:
            messagebox.showwarning("Error", "Enter a message!")
            return
            
        try:
            h = self.simple_hash(message)
            
            # Per-message secret k
            k = random.randint(1, self.dss_q - 1)
            
            # r = (g^k mod p) mod q
            self.dss_r = pow(self.dss_g, k, self.dss_p) % self.dss_q
            
            # s = (k^-1 * (h + x*r)) mod q
            # Calculate k inverse
            k_inv = None
            for i in range(1, self.dss_q):
                if (k * i) % self.dss_q == 1:
                    k_inv = i
                    break
            
            if k_inv is None:
                raise ValueError("Could not find modular inverse for k")
                
            self.dss_s = (k_inv * (h + self.dss_x * self.dss_r)) % self.dss_q
            
            self.dss_sig_label.config(text=f"Signature (r, s): ({self.dss_r}, {self.dss_s})\n(Message Hash: {h}, k: {k})")
            self.set_status("Message Signed")
            
        except Exception as ex:
            messagebox.showerror("Error", f"Signing Error: {str(ex)}")

    def dss_verify(self):
        """Verify DSS signature"""
        if not hasattr(self, 'dss_r') or not hasattr(self, 'dss_s'):
            messagebox.showwarning("Error", "Sign a message first!")
            return
            
        message = self.dss_msg_entry.get()
        
        try:
            h = self.simple_hash(message)
            
            # w = s^-1 mod q
            w = None
            for i in range(1, self.dss_q):
                if (self.dss_s * i) % self.dss_q == 1:
                    w = i
                    break
            
            if w is None:
                self.dss_verify_label.config(text="❌ Invalid: Inverse not found", foreground="#ff6b6b")
                return

            u1 = (h * w) % self.dss_q
            u2 = (self.dss_r * w) % self.dss_q
            
            v = ((pow(self.dss_g, u1, self.dss_p) * pow(self.dss_y, u2, self.dss_p)) % self.dss_p) % self.dss_q
            
            if v == self.dss_r:
                self.dss_verify_label.config(text=f"✓ Valid Signature (v={v}, r={self.dss_r})", foreground="#0f0")
            else:
                self.dss_verify_label.config(text=f"❌ Invalid Signature (v={v}, r={self.dss_r})", foreground="#ff6b6b")
                
            self.set_status("Verification Complete")
            
        except Exception as ex:
            messagebox.showerror("Error", f"Verification Error: {str(ex)}")


    # ==================== DIFFIE-HELLMAN TAB ====================

    def create_hellman_tab(self):
        """Create Diffie-Hellman Key Exchange tab"""
        dh_frame = ttk.Frame(self.notebook, style='Dark.TFrame')
        self.notebook.add(dh_frame, text='🤝 Diffie-Hellman')
        
        # Info frame
        info_frame = ttk.Frame(dh_frame, style='Card.TFrame')
        info_frame.pack(fill='x', padx=15, pady=15)
        
        ttk.Label(info_frame, text="Diffie-Hellman Key Exchange", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        self.dh_p = 23
        self.dh_g = 5
        
        info = f"Public Parameters:\nPrime (p) = {self.dh_p}\nGenerator (g) = {self.dh_g}"
        ttk.Label(info_frame, text=info, style='Info.TLabel', justify='left').pack(anchor='w', padx=10, pady=(0, 10))
        
        # Private Keys Input
        input_frame = ttk.Frame(dh_frame, style='Card.TFrame')
        input_frame.pack(fill='x', padx=15, pady=(0, 15))
        
        ttk.Label(input_frame, text="Private Keys", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        # Alice -> Sender
        sender_frame = ttk.Frame(input_frame, style='Dark.TFrame')
        sender_frame.pack(fill='x', padx=10, pady=5)
        ttk.Label(sender_frame, text="Sender Private Key (a):", style='Info.TLabel', width=25).pack(side='left')
        self.dh_sender_priv = tk.Entry(sender_frame, bg='#0a0e27', fg='#0f0', font=('Consolas', 11), insertbackground='#0f0', width=10)
        self.dh_sender_priv.pack(side='left', padx=5)
        self.dh_sender_priv.insert(0, "6")
        ttk.Button(sender_frame, text="📂", width=3, style='Secondary.TButton',
                   command=lambda: self.load_file_to_widget(self.dh_sender_priv)).pack(side='left', padx=5)
        
        # Bob -> Receiver
        receiver_frame = ttk.Frame(input_frame, style='Dark.TFrame')
        receiver_frame.pack(fill='x', padx=10, pady=5)
        ttk.Label(receiver_frame, text="Receiver Private Key (b):", style='Info.TLabel', width=25).pack(side='left')
        self.dh_receiver_priv = tk.Entry(receiver_frame, bg='#0a0e27', fg='#0f0', font=('Consolas', 11), insertbackground='#0f0', width=10)
        self.dh_receiver_priv.pack(side='left', padx=5)
        self.dh_receiver_priv.insert(0, "15")
        ttk.Button(receiver_frame, text="📂", width=3, style='Secondary.TButton',
                   command=lambda: self.load_file_to_widget(self.dh_receiver_priv)).pack(side='left', padx=5)
        
        # Attack Simulation Checkbox
        self.dh_attack_var = tk.BooleanVar(value=False)
        atk_chk = tk.Checkbutton(input_frame, text="⚠️ Simulate Man-in-the-Middle Attack", 
                                variable=self.dh_attack_var,
                                bg='#16213e', fg='#ff6b6b', selectcolor='#0a0e27',
                                activebackground='#16213e', activeforeground='#ff6b6b',
                                font=('Consolas', 10, 'bold'))
        atk_chk.pack(anchor='w', padx=10, pady=(10, 0))
        
        ttk.Button(input_frame, text="🔄 Exchange Keys", 
                  style='Action.TButton',
                  command=self.run_diffie_hellman).pack(anchor='w', padx=10, pady=10)
                  
        # Results frame
        res_frame = ttk.Frame(dh_frame, style='Card.TFrame')
        res_frame.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        
        res_header = ttk.Frame(res_frame, style='Card.TFrame')
        res_header.pack(fill='x', padx=10, pady=(10, 5))
        ttk.Label(res_header, text="Exchange Process", style='Header.TLabel').pack(side='left')
        
        ttk.Button(res_header, text="💾 Save Log", style='Secondary.TButton',
                   command=lambda: self.save_text_to_file(self.dh_log.get('1.0', 'end-1c'))).pack(side='right')
        
        self.dh_log = scrolledtext.ScrolledText(res_frame, height=10, 
                                                bg='#0a0e27', fg='#00d4ff',
                                                font=('Consolas', 10),
                                                state='disabled', relief='flat')
        self.dh_log.pack(fill='both', expand=True, padx=10, pady=10)

    def run_diffie_hellman(self):
        """Execute Diffie-Hellman Key Exchange"""
        try:
            a = int(self.dh_sender_priv.get())
            b = int(self.dh_receiver_priv.get())
            
            log = f"Using Public Parameters: p={self.dh_p}, g={self.dh_g}\n"
            log += "-" * 50 + "\n"
            
            # Calculate Public Keys
            # A = g^a mod p
            A = pow(self.dh_g, a, self.dh_p)
            # B = g^b mod p
            B = pow(self.dh_g, b, self.dh_p)
            
            log += f"Sender (A) computes Public Key A = {self.dh_g}^{a} mod {self.dh_p} = {A}\n"
            log += f"Receiver (B) computes Public Key B = {self.dh_g}^{b} mod {self.dh_p} = {B}\n"
            log += "-" * 50 + "\n"
            log += "Exchanging Public Keys...\n"
            
            # ATTACK SIMULATION
            real_B = B
            real_A = A
            
            if self.dh_attack_var.get():
                log += "\n" + "!" * 50 + "\n"
                log += "⚠️  MITM ATTACK: Attacker intercepted the keys!\n"
                log += f"   - Intercepted A={A}, replaced with A'={A+1}\n"
                log += f"   - Intercepted B={B}, replaced with B'={B+1}\n"
                log += "!" * 50 + "\n\n"
                # Tamper with keys
                A = A + 1
                B = B + 1
            
            log += "-" * 50 + "\n"
            
            # Calculate Shared Secret
            # Sender: s = B^a mod p
            s_sender = pow(B, a, self.dh_p)
            # Receiver: s = A^b mod p
            s_receiver = pow(A, b, self.dh_p)
            
            log += f"Sender receives B={B}, computes secret:   {B}^{a} mod {self.dh_p} = {s_sender}\n"
            log += f"Receiver receives A={A}, computes secret: {A}^{b} mod {self.dh_p} = {s_receiver}\n"
            
            log += "=" * 50 + "\n"
            if s_sender == s_receiver:
                log += f"✓ SUCCESS: Shared Secret Established: {s_sender}\n"
            else:
                log += f"❌ FAILURE: Secrets do not match! ({s_sender} vs {s_receiver})\n"
            
            self.dh_log.config(state='normal')
            self.dh_log.delete('1.0', 'end')
            self.dh_log.insert('1.0', log)
            self.dh_log.config(state='disabled')
            
            self.set_status("Key Exchange Complete")
            
        except ValueError:
            messagebox.showerror("Input Error", "Private keys must be integers!")
        except Exception as ex:
            messagebox.showerror("Error", f"Diffie-Hellman failed: {str(ex)}")

    # ==================== FULL DES TAB ====================

    def create_full_des_tab(self):
        """Create Full DES Encryption/Decryption encryption tab"""
        fdes_frame = ttk.Frame(self.notebook, style='Dark.TFrame')
        self.notebook.add(fdes_frame, text='🔒 Full DES')

        # Input Frame
        input_frame = ttk.Frame(fdes_frame, style='Card.TFrame')
        input_frame.pack(fill='x', padx=15, pady=15)

        ttk.Label(input_frame, text="Full DES Encryption/Decryption", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))

        # Key Input
        key_frame = ttk.Frame(input_frame, style='Dark.TFrame')
        key_frame.pack(fill='x', padx=10, pady=5)
        ttk.Label(key_frame, text="64-bit Hex Key (16 chars):", style='Info.TLabel').pack(anchor='w')
        
        self.fdes_key = tk.Entry(key_frame, bg='#0a0e27', fg='#0f0', font=('Consolas', 11), width=40, insertbackground='#0f0', relief='flat')
        self.fdes_key.pack(side='left', fill='x', expand=True, pady=5)
        self.fdes_key.insert(0, "AABB09182736CCDD")
        
        ttk.Button(key_frame, text="📂", width=3, style='Secondary.TButton', 
                   command=lambda: self.load_file_to_widget(self.fdes_key)).pack(side='left', padx=(5, 0))

        # Text Input
        msg_frame = ttk.Frame(input_frame, style='Dark.TFrame')
        msg_frame.pack(fill='x', padx=10, pady=5)
        ttk.Label(msg_frame, text="64-bit Hex Message (16 chars):", style='Info.TLabel').pack(anchor='w')
        
        self.fdes_input = tk.Entry(msg_frame, bg='#0a0e27', fg='#0f0', font=('Consolas', 11), width=40, insertbackground='#0f0', relief='flat')
        self.fdes_input.pack(side='left', fill='x', expand=True, pady=5)
        self.fdes_input.insert(0, "123456ABCD132536")
        
        ttk.Button(msg_frame, text="📂", width=3, style='Secondary.TButton', 
                   command=lambda: self.load_file_to_widget(self.fdes_input)).pack(side='left', padx=(5, 0))

        # Buttons
        btn_frame = ttk.Frame(input_frame, style='Card.TFrame')
        btn_frame.pack(fill='x', padx=10, pady=10)

        ttk.Button(btn_frame, text="🔒 Encrypt", style='Action.TButton', command=lambda: self.run_full_des('encrypt')).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="🔓 Decrypt", style='Action.TButton', command=lambda: self.run_full_des('decrypt')).pack(side='left', padx=5)

        # Output Frame
        output_frame = ttk.Frame(fdes_frame, style='Card.TFrame')
        output_frame.pack(fill='both', expand=True, padx=15, pady=(0, 15))

        res_header = ttk.Frame(output_frame, style='Card.TFrame')
        res_header.pack(fill='x', padx=10, pady=(10, 5))
        ttk.Label(res_header, text="Result (Hex):", style='Header.TLabel').pack(side='left')
        
        self.fdes_result = tk.Label(output_frame, bg='#0a0e27', fg='#00d4ff', font=('Consolas', 12, 'bold'), anchor='w', padx=10, pady=10)
        self.fdes_result.pack(fill='x', padx=10)
        
        res_actions = ttk.Frame(output_frame, style='Card.TFrame')
        res_actions.pack(fill='x', padx=10, pady=5)
        ttk.Button(res_actions, text="📋 Copy", style='Secondary.TButton', 
                   command=lambda: self.copy_text(self.fdes_result.cget('text'))).pack(side='left')
        ttk.Button(res_actions, text="💾 Save", style='Secondary.TButton', 
                   command=lambda: self.save_text_to_file(self.fdes_result.cget('text'))).pack(side='left', padx=5)
        ttk.Button(res_actions, text="⬇ To Input", style='Secondary.TButton',
                   command=self.fdes_use_result_as_input).pack(side='left', padx=5)
        
        log_header_frame = ttk.Frame(output_frame, style='Card.TFrame')
        log_header_frame.pack(fill='x', padx=10, pady=(15, 5))
        ttk.Label(log_header_frame, text="Round Logs:", style='Header.TLabel').pack(side='left')
        
        ttk.Button(log_header_frame, text="💾 Save Logs", style='Secondary.TButton',
                   command=lambda: self.save_text_to_file(self.fdes_log.get('1.0', 'end-1c'))).pack(side='right')

        self.fdes_log = scrolledtext.ScrolledText(output_frame, bg='#0a0e27', fg='#0f0', font=('Consolas', 9), height=10, relief='flat', state='disabled')
        self.fdes_log.pack(fill='both', expand=True, padx=10, pady=10)

    def run_full_des(self, mode):
        key = self.fdes_key.get().strip()
        text = self.fdes_input.get().strip()

        if len(key) != 16 or len(text) != 16:
            messagebox.showerror("Error", "Key and Input must be exactly 16 Hex characters!")
            return

        try:
            if mode == 'encrypt':
                res, logs = FullDES.encrypt(text, key)
                self.fdes_result.config(text=res, fg='#ff6b6b')
            else:
                res, logs = FullDES.decrypt(text, key)
                self.fdes_result.config(text=res, fg='#0f0')

            self.fdes_log.config(state='normal')
            self.fdes_log.delete('1.0', 'end')
            self.fdes_log.insert('1.0', "\n".join(logs))
            self.fdes_log.config(state='disabled')
            
            self.set_status(f"Full DES {mode.title()} successful")


        except Exception as ex:
            messagebox.showerror("Error", f"Execution failed: {str(ex)}")

    def fdes_use_result_as_input(self):
        """Transfer result text to input field"""
        res = self.fdes_result.cget('text').strip()
        if res:
            self.fdes_input.delete(0, 'end')
            self.fdes_input.insert(0, res)
            self.set_status("Copied Result to Input")


    # ==================== SHA FAMILY TAB ====================
    
    def create_sha_family_tab(self):
        """Create SHA Family tab with subtabs"""
        sha_frame = ttk.Frame(self.notebook, style='Dark.TFrame')
        self.notebook.add(sha_frame, text='🛡️ SHA Family')
        
        # Sub-notebook for different SHAs
        sha_tabs = ttk.Notebook(sha_frame)
        sha_tabs.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Add tabs for each variant
        for algo in ['SHA-256', 'SHA-384', 'SHA-224', 'SHA-512']:
            self.create_single_sha_tab(sha_tabs, algo)
            
    def create_single_sha_tab(self, parent, algo_name):
        """Helper to create a tab for a specific SHA algo"""
        tab = ttk.Frame(parent, style='Dark.TFrame')
        parent.add(tab, text=algo_name)
        
        # Input
        input_frame = ttk.Frame(tab, style='Card.TFrame')
        input_frame.pack(fill='x', padx=15, pady=15)
        
        ttk.Label(input_frame, text=f"{algo_name} Hash", style='Header.TLabel').pack(anchor='w', padx=10, pady=(10, 5))
        
        inp_container = ttk.Frame(input_frame, style='Dark.TFrame')
        inp_container.pack(fill='x', padx=10)
        
        inp = tk.Entry(inp_container, bg='#0a0e27', fg='#0f0', font=('Consolas', 11), relief='flat')
        inp.pack(side='left', fill='x', expand=True, pady=5)
        
        # Output
        out_frame = ttk.Frame(tab, style='Card.TFrame')
        out_frame.pack(fill='x', padx=15)
        
        ttk.Label(out_frame, text="Digest:", style='Header.TLabel').pack(anchor='w', padx=10, pady=5)
        out_lbl = tk.Label(out_frame, bg='#0a0e27', fg='#00d4ff', font=('Consolas', 10), anchor='w', wraplength=700)
        out_lbl.pack(fill='x', padx=10, pady=10)
        
        # Actions for Output
        out_actions = ttk.Frame(out_frame, style='Card.TFrame')
        out_actions.pack(fill='x', padx=10, pady=(0, 10))
        ttk.Button(out_actions, text="📋 Copy", style='Secondary.TButton', 
                   command=lambda: self.copy_text(out_lbl.cget('text'))).pack(side='left')
        ttk.Button(out_actions, text="💾 Save", style='Secondary.TButton', 
                   command=lambda: self.save_text_to_file(out_lbl.cget('text'))).pack(side='left', padx=5)
        
        # Buttons
        btn_frame = ttk.Frame(input_frame, style='Dark.TFrame')
        btn_frame.pack(fill='x', padx=10, pady=10)
        
        def run_hash():
            text = inp.get()
            if not text: return
            try:
                if algo_name == 'SHA-256': m = hashlib.sha256()
                elif algo_name == 'SHA-384': m = hashlib.sha384()
                elif algo_name == 'SHA-224': m = hashlib.sha224()
                elif algo_name == 'SHA-512': m = hashlib.sha512()
                m.update(text.encode('utf-8'))
                out_lbl.config(text=m.hexdigest())
                self.set_status(f"{algo_name} Calculated")
            except Exception as e:
                messagebox.showerror("Error", str(e))
                
        ttk.Button(btn_frame, text="⚡ Calculate", style='Action.TButton', command=run_hash).pack(side='left')
        ttk.Button(btn_frame, text="📂 Load File", style='Secondary.TButton', command=lambda: self.load_file_to_widget(inp)).pack(side='left', padx=5)

    # ==================== UTILITY FUNCTIONS ====================
    
    def save_text_to_file(self, content, default_ext=".txt"):
        """Save text content to a file"""
        if not content or content.strip() == "":
            messagebox.showinfo("No Content", "Nothing to save!")
            return
            
        try:
            filename = filedialog.asksaveasfilename(
                title="Save As",
                defaultextension=default_ext,
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
            )
            
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.set_status(f"Saved to {filename}")
                messagebox.showinfo("Success", f"File saved successfully to:\n{filename}")
                
        except Exception as ex:
            messagebox.showerror("Error", f"Failed to save file: {str(ex)}")

    def load_file_to_widget(self, widget):
        """Load text from file into a widget (Entry or Text)"""
        try:
            filename = filedialog.askopenfilename(
                title="Select Text File",
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
            )
            
            if filename:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                # Handle different widget types
                if isinstance(widget, tk.Entry):
                    widget.delete(0, 'end')
                    widget.insert(0, content)
                elif isinstance(widget, tk.Text) or isinstance(widget, scrolledtext.ScrolledText):
                    widget.config(state='normal')
                    widget.delete('1.0', 'end')
                    widget.insert('1.0', content)
                    # Don't disable here to allow user editing
                
                self.set_status(f"Loaded content from {filename}")
                messagebox.showinfo("Success", f"File loaded successfully from:\n{filename}")
                
        except Exception as ex:
            messagebox.showerror("Error", f"Failed to load file: {str(ex)}")

    def copy_to_clipboard(self, text_widget):
        """Copy text from a text widget to clipboard"""
        try:
            content = text_widget.get('1.0', 'end-1c')
            if content:
                self.root.clipboard_clear()
                self.root.clipboard_append(content)
                self.set_status("Copied to clipboard")
            else:
                messagebox.showinfo("No Content", "Nothing to copy!")
        except Exception as ex:
            messagebox.showerror("Error", f"Copy failed: {str(ex)}")
    
    def copy_text(self, text):
        """Copy plain text to clipboard"""
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.set_status("Copied to clipboard")
        else:
            messagebox.showinfo("No Content", "Nothing to copy!")


if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityToolkit(root)
    root.mainloop()
