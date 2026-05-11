import tkinter as tk
from tkinter import messagebox, filedialog
import customtkinter as ctk
from PIL import Image, ImageTk
import os
import sys
import jwt
import datetime
import json
import secrets

try:
    from tinyec import registry
except ImportError:
    pass

import base64
import math

class CryptoEngine:
    @staticmethod
    def base64_encode(text):
        return base64.b64encode(text.encode('utf-8')).decode('utf-8')
        
    @staticmethod
    def base64_decode(text):
        return base64.b64decode(text.encode('utf-8')).decode('utf-8')

    @staticmethod
    def _caesar_cipher(text, key):
        res = ""
        for char in text:
            if char.isupper(): res += chr((ord(char) + key - 65) % 26 + 65)
            elif char.islower(): res += chr((ord(char) + key - 97) % 26 + 97)
            else: res += char
        return res

    @staticmethod
    def caesar_encrypt(text, key):
        key = int(key)
        if not (1 <= key <= 25): raise ValueError("Shift must be between 1 and 25")
        return CryptoEngine._caesar_cipher(text, key)
        
    @staticmethod
    def caesar_decrypt(text, key):
        key = int(key)
        if not (1 <= key <= 25): raise ValueError("Shift must be between 1 and 25")
        return CryptoEngine._caesar_cipher(text, -key)

    @staticmethod
    def _mod_inverse(k):
        for i in range(1, 26):
            if (k * i) % 26 == 1: return i
        raise ValueError("Key must be coprime to 26")

    @staticmethod
    def multiplicative_encrypt(text, key):
        key = int(key)
        CryptoEngine._mod_inverse(key) # Validates coprimality
        res = ""
        for char in text:
            if char.isalpha():
                c = char.upper()
                enc = chr(((ord(c) - 65) * key) % 26 + 65)
                res += enc if char.isupper() else enc.lower()
            else: res += char
        return res

    @staticmethod
    def multiplicative_decrypt(text, key):
        inv = CryptoEngine._mod_inverse(int(key))
        return CryptoEngine.multiplicative_encrypt(text, inv)

    @staticmethod
    def railfence_encrypt(text, key):
        key = int(key)
        if key < 2: raise ValueError("Number of rails must be at least 2")
        rails = [''] * key
        r, dir = 0, 1
        for char in text:
            rails[r] += char
            if r == 0: dir = 1
            elif r == key - 1: dir = -1
            r += dir
        return "".join(rails)

    @staticmethod
    def railfence_decrypt(text, key):
        key = int(key)
        if key < 2: raise ValueError("Number of rails must be at least 2")
        n = len(text)
        pattern = []
        r, dir = 0, 1
        for _ in range(n):
            pattern.append(r)
            if r == 0: dir = 1
            elif r == key - 1: dir = -1
            r += dir
        indices = sorted(range(n), key=lambda i: (pattern[i], i))
        res = [''] * n
        for c_idx, p_idx in enumerate(indices):
            res[p_idx] = text[c_idx]
        return "".join(res)

    @staticmethod
    def substitution_encrypt(text, key):
        key = key.upper()
        if len(key) != 26 or not key.isalpha() or len(set(key)) != 26:
            raise ValueError("Key must be exactly 26 unique alphabetic characters")
        res = ""
        for char in text:
            if char.isalpha():
                idx = ord(char.upper()) - 65
                res += key[idx] if char.isupper() else key[idx].lower()
            else: res += char
        return res

    @staticmethod
    def substitution_decrypt(text, key):
        key = key.upper()
        if len(key) != 26 or not key.isalpha() or len(set(key)) != 26:
            raise ValueError("Key must be exactly 26 unique alphabetic characters")
        res = ""
        for char in text:
            if char.isalpha():
                idx = key.find(char.upper())
                res += chr(idx + 65) if char.isupper() else chr(idx + 97)
            else: res += char
        return res

    @staticmethod
    def transposition_encrypt(text, key):
        if not key.isdigit() or len(set(key)) != len(key):
            raise ValueError("Column key must contain unique digits (e.g. 1320)")
        order = {int(v): i for i, v in enumerate(key)}
        res = ""
        for k in sorted(order.keys()):
            for i in range(order[k], len(text), len(key)):
                res += text[i]
        return res

    @staticmethod
    def transposition_decrypt(text, key):
        if not key.isdigit() or len(set(key)) != len(key):
            raise ValueError("Column key must contain unique digits (e.g. 1320)")
        num_cols = len(key)
        num_rows = math.ceil(len(text) / num_cols)
        last_row_len = len(text) % num_cols
        short_cols = set(range(last_row_len, num_cols)) if last_row_len != 0 else set()
        
        order = {int(v): i for i, v in enumerate(key)}
        col_data = {}
        idx = 0
        for k in sorted(order.keys()):
            col_pos = order[k]
            length = num_rows - 1 if col_pos in short_cols else num_rows
            col_data[col_pos] = text[idx:idx + length]
            idx += length
            
        res = ""
        for row in range(num_rows):
            for col in range(num_cols):
                if row < len(col_data[col]):
                    res += col_data[col][row]
        return res

    @staticmethod
    def vigenere_encrypt(text, key):
        key = key.upper()
        if not key.isalpha(): raise ValueError("Keyword must contain only alphabetic characters")
        res = ""
        k_idx = 0
        for char in text:
            if char.isalpha():
                shift = ord(key[k_idx % len(key)]) - 65
                if char.isupper(): res += chr((ord(char) - 65 + shift) % 26 + 65)
                else: res += chr((ord(char) - 97 + shift) % 26 + 97)
                k_idx += 1
            else: res += char
        return res

    @staticmethod
    def vigenere_decrypt(text, key):
        key = key.upper()
        if not key.isalpha(): raise ValueError("Keyword must contain only alphabetic characters")
        res = ""
        k_idx = 0
        for char in text:
            if char.isalpha():
                shift = ord(key[k_idx % len(key)]) - 65
                if char.isupper(): res += chr((ord(char) - 65 - shift + 26) % 26 + 65)
                else: res += chr((ord(char) - 97 - shift + 26) % 26 + 97)
                k_idx += 1
            else: res += char
        return res

    @staticmethod
    def xor_encrypt(text, key):
        if not key: raise ValueError("XOR key cannot be empty")
        res = ""
        for i, char in enumerate(text):
            res += chr(ord(char) ^ ord(key[i % len(key)]))
        return res

    @staticmethod
    def xor_decrypt(text, key):
        if not key: raise ValueError("XOR key cannot be empty")
        return CryptoEngine.xor_encrypt(text, key)

    @staticmethod
    def jwt_encrypt(text, key):
        import jwt, datetime, json
        
        # Try to parse text as JSON, otherwise wrap it in a 'data' field
        try:
            payload_data = json.loads(text)
            if not isinstance(payload_data, dict):
                payload_data = {"data": payload_data}
        except:
            payload_data = {"data": text}
            
        payload = payload_data.copy()
        payload["iat"] = datetime.datetime.utcnow()
        payload["exp"] = datetime.datetime.utcnow() + datetime.timedelta(minutes=60)
        
        token = jwt.encode(payload, key, algorithm="HS256")
        return token.decode('utf-8') if isinstance(token, bytes) else token

    @staticmethod
    def jwt_decrypt(text, key):
        import jwt, json
        try:
            decoded = jwt.decode(text.strip(), key, algorithms=["HS256"])
            return f"✅ Valid Signature!\n\nDecoded Payload:\n{json.dumps(decoded, indent=2)}"
        except jwt.ExpiredSignatureError:
            raise Exception("Token expired!")
        except jwt.InvalidSignatureError:
            raise Exception("Invalid signature!")
        except Exception as e:
            raise Exception(f"Invalid token: {str(e)}")

class CryptoToolkit:
    def __init__(self, root):
        self.root = root
        self.root.title("💎 Crypto Toolkit")
        self.root.geometry("1100x750")
        self.root.minsize(1000, 650)
        
        # Cyber Theme Configuration
        ctk.set_appearance_mode("dark")
        self.bg_color = "#050B14"
        self.frame_bg = "#0A1424"
        self.cyan_accent = "#22d3ee"
        self.text_color = "#e2e8f0"
        
        self.root.configure(fg_color=self.bg_color)
        
        # Load explanations
        self.explanations = self.load_explanations()
        
        self.main_container = ctk.CTkFrame(self.root, fg_color="transparent")
        self.main_container.pack(fill='both', expand=True)
        
        self.create_landing_page()
        self.create_status_bar()

    def load_explanations(self):
        explanations = {}
        summary_dir = os.path.join(os.path.dirname(__file__), 'Summaries')
        if not os.path.exists(summary_dir):
            return explanations
        
        file_map = {
            'base64.txt': 'Base64',
            'caesar.txt': 'Caesar Cipher',
            'multiplicative.txt': 'Multiplicative Cipher',
            'railfence.txt': 'Rail Fence Cipher',
            'substitution.txt': 'Simple Substitution Cipher',
            'transposition.txt': 'Columnar Transposition Cipher',
            'vigenere.txt': 'Vigenère Cipher',
            'xor.txt': 'XOR Cipher',
            'jwtexplain.txt': 'JWT',
            'ecc.txt': 'ECC'
        }
        
        for file_name, algo in file_map.items():
            path = os.path.join(summary_dir, file_name)
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8') as f:
                    explanations[algo] = f.read().strip()
        return explanations

    def create_status_bar(self):
        self.status_var = tk.StringVar()
        self.status_var.set("Ready | Mode: Active | Security Level: High")
        
        self.status_bar = ctk.CTkLabel(self.root, textvariable=self.status_var, 
                                       fg_color="#02060d", text_color=self.cyan_accent,
                                       height=30, anchor="w", font=('Consolas', 11), padx=20)
        self.status_bar.pack(side='bottom', fill='x')

    def set_status(self, msg):
        import time
        t = time.strftime("%H:%M:%S")
        self.status_var.set(f"{msg} | Mode: Active | Time: {t} | Security Level: High")

    def create_landing_page(self):
        for widget in self.main_container.winfo_children():
            widget.destroy()
            
        center_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        center_frame.place(relx=0.5, rely=0.5, anchor='center')
        
        ctk.CTkLabel(center_frame, text="💎 CRYPTO TOOLKIT", font=('Consolas', 40, 'bold'), text_color=self.cyan_accent).pack(pady=20)
        ctk.CTkLabel(center_frame, text="Select operation mode:", font=('Consolas', 16), text_color="#475569").pack(pady=(0, 40))
        
        btn_frame = ctk.CTkFrame(center_frame, fg_color="transparent")
        btn_frame.pack()
        
        ctk.CTkButton(btn_frame, text="⚙️ CODES\n\n(Run Algorithms)", font=('Consolas', 16, 'bold'), 
                      width=200, height=100, corner_radius=10, border_width=2, border_color=self.cyan_accent,
                      fg_color=self.frame_bg, hover_color="#102A4A", text_color=self.cyan_accent,
                      command=self.show_codes_view).pack(side='left', padx=20)
                      
        ctk.CTkButton(btn_frame, text="📖 EXPLANATION\n\n(Learn Concepts)", font=('Consolas', 16, 'bold'), 
                      width=200, height=100, corner_radius=10, border_width=2, border_color=self.cyan_accent,
                      fg_color=self.frame_bg, hover_color="#102A4A", text_color=self.cyan_accent,
                      command=self.show_explanation_view).pack(side='left', padx=20)

    def create_header(self, parent, view_name):
        header_frame = ctk.CTkFrame(parent, fg_color="transparent", height=60)
        header_frame.pack(fill='x', padx=20, pady=(10, 0))
        
        ctk.CTkButton(header_frame, text="⬅ Back", width=80, fg_color="#1e293b", hover_color="#334155", 
                      command=self.create_landing_page).pack(side='left')
        
        title_container = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_container.pack(side='top', expand=True)
        
        ctk.CTkLabel(title_container, text=f"CRYPTO TOOLKIT - {view_name.upper()}", 
                     text_color=self.cyan_accent, font=('Consolas', 18, 'bold')).pack()

    def show_codes_view(self):
        for widget in self.main_container.winfo_children():
            widget.destroy()
        self.create_header(self.main_container, "Codes")
        
        # Custom Premium Tab Navigation
        self.tab_nav_frame = ctk.CTkScrollableFrame(self.main_container, height=60, orientation="horizontal", fg_color="transparent", bg_color="transparent")
        self.tab_nav_frame.pack(fill='x', padx=20, pady=(10, 0))
        
        self.tab_content_frame = ctk.CTkFrame(self.main_container, fg_color=self.bg_color, border_width=1, border_color=self.cyan_accent, corner_radius=10)
        self.tab_content_frame.pack(fill='both', expand=True, padx=20, pady=(10, 20))
        
        self.algo_frames = {}
        self.nav_buttons = {}
        
        def select_tab(name):
            for btn_name, btn in self.nav_buttons.items():
                if btn_name == name:
                    btn.configure(fg_color=self.cyan_accent, text_color="#000000", border_color=self.cyan_accent)
                else:
                    btn.configure(fg_color=self.frame_bg, text_color=self.cyan_accent, border_color="#1e293b")
            
            for frame_name, frame in self.algo_frames.items():
                if frame_name == name:
                    frame.pack(fill='both', expand=True, padx=5, pady=5)
                else:
                    frame.pack_forget()
        
        algorithms = [
            ("Base64", "Text", None, CryptoEngine.base64_encode, CryptoEngine.base64_decode),
            ("Caesar", "Plaintext", "Shift (1-25)", CryptoEngine.caesar_encrypt, CryptoEngine.caesar_decrypt),
            ("Multiplicative", "Plaintext", "Key (coprime to 26)", CryptoEngine.multiplicative_encrypt, CryptoEngine.multiplicative_decrypt),
            ("Rail Fence", "Plaintext", "Number of Rails", CryptoEngine.railfence_encrypt, CryptoEngine.railfence_decrypt),
            ("Substitution", "Plaintext", "Key Alphabet (26 chars)", CryptoEngine.substitution_encrypt, CryptoEngine.substitution_decrypt),
            ("Transposition", "Plaintext", "Column Key (e.g. 1320)", CryptoEngine.transposition_encrypt, CryptoEngine.transposition_decrypt),
            ("Vigenère", "Plaintext", "Keyword", CryptoEngine.vigenere_encrypt, CryptoEngine.vigenere_decrypt),
            ("XOR", "Plaintext", "XOR Key", CryptoEngine.xor_encrypt, CryptoEngine.xor_decrypt),
            ("JWT", None, None, None, None),
            ("ECC", None, None, None, None)
        ]
        
        for name, txt_lbl, key_lbl, enc_func, dec_func in algorithms:
            btn = ctk.CTkButton(self.tab_nav_frame, text=name.upper(), font=('Consolas', 13, 'bold'), 
                                corner_radius=20, border_width=1, height=40, hover_color="#0284c7",
                                command=lambda n=name: select_tab(n))
            btn.pack(side='left', padx=5, pady=5)
            self.nav_buttons[name] = btn
            
            frame = ctk.CTkFrame(self.tab_content_frame, fg_color="transparent")
            self.algo_frames[name] = frame
            
            if name == "JWT":
                self.create_jwt_tab(frame)
            elif name == "ECC":
                self.create_ecc_tab(frame)
            else:
                self.create_algo_tab(frame, name, txt_lbl, key_lbl, enc_func, dec_func)
                
        if algorithms:
            select_tab(algorithms[0][0])

    def create_algo_tab(self, parent, name, txt_lbl, key_lbl, enc_func, dec_func):
        parent.grid_columnconfigure((0, 1, 2), weight=1)
        parent.grid_rowconfigure(0, weight=1)
        
        frame_kwargs = {"fg_color": self.frame_bg, "corner_radius": 10, "border_width": 1, "border_color": self.cyan_accent}
        
        left_frame = ctk.CTkFrame(parent, **frame_kwargs)
        left_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        
        ctk.CTkLabel(left_frame, text=f"■ {txt_lbl.upper()} INPUT", font=('Consolas', 14, 'bold'), text_color=self.cyan_accent).pack(anchor='w', padx=15, pady=(15, 5))
        txt_input = ctk.CTkTextbox(left_frame, fg_color="#030712", text_color=self.text_color, font=('Consolas', 13), border_width=1, border_color="#1e293b", corner_radius=5)
        txt_input.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        
        center_frame = ctk.CTkFrame(parent, fg_color="transparent")
        center_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        
        if key_lbl:
            key_box = ctk.CTkFrame(center_frame, **frame_kwargs)
            key_box.pack(fill='x', pady=(0, 20))
            ctk.CTkLabel(key_box, text=f"■ ENCRYPTION KEY", font=('Consolas', 14, 'bold'), text_color=self.cyan_accent).pack(anchor='w', padx=15, pady=(15, 5))
            ctk.CTkLabel(key_box, text=key_lbl, text_color="#94a3b8", font=('Consolas', 11)).pack(anchor='w', padx=15)
            key_input = ctk.CTkEntry(key_box, fg_color="#030712", text_color=self.cyan_accent, font=('Consolas', 14), border_width=1, border_color="#1e293b", height=40)
            key_input.pack(fill='x', padx=15, pady=(5, 15))
        else:
            key_input = None
            
        action_box = ctk.CTkFrame(center_frame, **frame_kwargs)
        action_box.pack(fill='x')
        ctk.CTkLabel(action_box, text=f"■ EXECUTE ALGORITHM", font=('Consolas', 14, 'bold'), text_color=self.cyan_accent).pack(anchor='w', padx=15, pady=(15, 10))
        
        state = {"last_was_encrypt": False}
        
        def process(is_encrypt):
            if not is_encrypt and state["last_was_encrypt"]:
                prev_out = out_txt.get("1.0", tk.END).strip()
                if prev_out:
                    txt_input.delete("1.0", tk.END)
                    txt_input.insert(tk.END, prev_out)
                    
            text = txt_input.get("1.0", tk.END).strip()
            if not text: return
            
            key = key_input.get().strip() if key_input else None
            if key_lbl and not key: return
            
            try:
                func = enc_func if is_encrypt else dec_func
                res = func(text, key) if key_lbl else func(text)
                
                out_txt.configure(state='normal')
                out_txt.delete("1.0", tk.END)
                out_txt.insert(tk.END, str(res))
                out_txt.configure(text_color="#f87171" if is_encrypt else "#4ade80")
                out_txt.configure(state='disabled')
                
                self.set_status(f"{name} {'Encryption' if is_encrypt else 'Decryption'} successful")
                state["last_was_encrypt"] = is_encrypt
            except Exception as e:
                messagebox.showerror("Error", str(e))
                self.set_status("Operation failed")

        btn_kwargs = {"font": ('Consolas', 14, 'bold'), "height": 45, "corner_radius": 5}
        ctk.CTkButton(action_box, text="🔒 ENCRYPT", fg_color="#10b981", hover_color="#059669", text_color="#ffffff", command=lambda: process(True), **btn_kwargs).pack(fill='x', padx=15, pady=(0, 10))
        ctk.CTkButton(action_box, text="🔓 DECRYPT", fg_color="#f59e0b", hover_color="#d97706", text_color="#ffffff", command=lambda: process(False), **btn_kwargs).pack(fill='x', padx=15, pady=(0, 15))

        right_frame = ctk.CTkFrame(parent, **frame_kwargs)
        right_frame.grid(row=0, column=2, padx=10, pady=10, sticky="nsew")
        
        ctk.CTkLabel(right_frame, text="■ ENCRYPTED OUTPUT", font=('Consolas', 14, 'bold'), text_color=self.cyan_accent).pack(anchor='w', padx=15, pady=(15, 5))
        out_txt = ctk.CTkTextbox(right_frame, fg_color="#030712", text_color=self.text_color, font=('Consolas', 13), border_width=1, border_color="#1e293b", corner_radius=5)
        out_txt.pack(fill='both', expand=True, padx=15, pady=(0, 10))
        out_txt.configure(state='disabled')
        
        def copy_out():
            self.root.clipboard_clear()
            self.root.clipboard_append(out_txt.get("1.0", tk.END).strip())
            self.set_status("Output copied to clipboard")
            
        def save_file():
            content = out_txt.get("1.0", tk.END).strip()
            if not content: return
            path = filedialog.asksaveasfilename(defaultextension=".txt")
            if path:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.set_status(f"Saved to {os.path.basename(path)}")
                
        def clear_all():
            txt_input.delete("1.0", tk.END)
            if key_input: key_input.delete(0, tk.END)
            out_txt.configure(state='normal')
            out_txt.delete("1.0", tk.END)
            out_txt.configure(text_color=self.text_color, state='disabled')
            self.set_status("Fields cleared")

        util_frame = ctk.CTkFrame(right_frame, fg_color="transparent")
        util_frame.pack(fill='x', padx=15, pady=(0, 15))
        
        ctk.CTkButton(util_frame, text="📋 COPY", width=80, fg_color="#1e293b", hover_color="#334155", command=copy_out).pack(side='left', expand=True, fill='x', padx=(0, 5))
        ctk.CTkButton(util_frame, text="💾 SAVE", width=80, fg_color="#1e293b", hover_color="#334155", command=save_file).pack(side='left', expand=True, fill='x', padx=5)
        ctk.CTkButton(util_frame, text="🗑 CLEAR", width=80, fg_color="#7f1d1d", hover_color="#991b1b", command=clear_all).pack(side='left', expand=True, fill='x', padx=(5, 0))

    def create_jwt_tab(self, parent):
        parent.grid_columnconfigure((0, 1), weight=1)
        parent.grid_rowconfigure(0, weight=1)
        frame_kwargs = {"fg_color": self.frame_bg, "corner_radius": 10, "border_width": 1, "border_color": self.cyan_accent}

        create_frame = ctk.CTkFrame(parent, **frame_kwargs)
        create_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        
        ctk.CTkLabel(create_frame, text="■ GENERATE JWT", font=('Consolas', 14, 'bold'), text_color=self.cyan_accent).pack(anchor='w', padx=15, pady=(15, 10))
        
        fields_frame = ctk.CTkFrame(create_frame, fg_color="transparent")
        fields_frame.pack(fill='x', padx=15)
        
        ctk.CTkLabel(fields_frame, text="User ID:", text_color="#94a3b8").grid(row=0, column=0, sticky='w', pady=5)
        self.jwt_id_ent = ctk.CTkEntry(fields_frame, fg_color="#030712", border_color="#1e293b")
        self.jwt_id_ent.grid(row=0, column=1, sticky='ew', padx=10, pady=5)
        
        ctk.CTkLabel(fields_frame, text="Name:", text_color="#94a3b8").grid(row=1, column=0, sticky='w', pady=5)
        self.jwt_name_ent = ctk.CTkEntry(fields_frame, fg_color="#030712", border_color="#1e293b")
        self.jwt_name_ent.grid(row=1, column=1, sticky='ew', padx=10, pady=5)
        
        ctk.CTkLabel(fields_frame, text="Email:", text_color="#94a3b8").grid(row=2, column=0, sticky='w', pady=5)
        self.jwt_email_ent = ctk.CTkEntry(fields_frame, fg_color="#030712", border_color="#1e293b")
        self.jwt_email_ent.grid(row=2, column=1, sticky='ew', padx=10, pady=5)
        
        fields_frame.columnconfigure(1, weight=1)
        
        ctk.CTkLabel(create_frame, text="Secret Key:", text_color="#94a3b8").pack(anchor='w', padx=15, pady=(10, 0))
        self.jwt_create_secret_ent = ctk.CTkEntry(create_frame, fg_color="#030712", border_color="#1e293b", show='*')
        self.jwt_create_secret_ent.pack(fill='x', padx=15, pady=(0, 15))
        
        ctk.CTkButton(create_frame, text="🔒 GENERATE JWT", fg_color="#10b981", hover_color="#059669", font=('Consolas', 14, 'bold'), command=self.generate_jwt).pack(fill='x', padx=15, pady=(0, 15))
        
        ctk.CTkLabel(create_frame, text="Generated Token:", text_color="#94a3b8").pack(anchor='w', padx=15)
        self.jwt_gen_token = ctk.CTkTextbox(create_frame, height=80, fg_color="#030712", text_color="#4ade80", border_color="#1e293b", border_width=1)
        self.jwt_gen_token.pack(fill='x', padx=15, pady=(0, 15))
        
        verify_frame = ctk.CTkFrame(parent, **frame_kwargs)
        verify_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        
        ctk.CTkLabel(verify_frame, text="■ VERIFY JWT", font=('Consolas', 14, 'bold'), text_color=self.cyan_accent).pack(anchor='w', padx=15, pady=(15, 10))
        
        ctk.CTkLabel(verify_frame, text="JWT Token:", text_color="#94a3b8").pack(anchor='w', padx=15)
        self.jwt_verify_token_ent = ctk.CTkTextbox(verify_frame, height=80, fg_color="#030712", text_color=self.cyan_accent, border_color="#1e293b", border_width=1)
        self.jwt_verify_token_ent.pack(fill='x', padx=15, pady=(0, 15))
        
        ctk.CTkLabel(verify_frame, text="Secret Key:", text_color="#94a3b8").pack(anchor='w', padx=15)
        self.jwt_verify_secret_ent = ctk.CTkEntry(verify_frame, fg_color="#030712", border_color="#1e293b", show='*')
        self.jwt_verify_secret_ent.pack(fill='x', padx=15, pady=(0, 15))
        
        ctk.CTkButton(verify_frame, text="🔓 VERIFY JWT", fg_color="#f59e0b", hover_color="#d97706", font=('Consolas', 14, 'bold'), command=self.verify_jwt).pack(fill='x', padx=15, pady=(0, 15))
        
        ctk.CTkLabel(verify_frame, text="Decoded Payload:", text_color="#94a3b8").pack(anchor='w', padx=15)
        self.jwt_result_area = ctk.CTkTextbox(verify_frame, fg_color="#030712", text_color=self.text_color, border_color="#1e293b", border_width=1)
        self.jwt_result_area.pack(fill='both', expand=True, padx=15, pady=(0, 15))

    def generate_jwt(self):
        user_id, name, email = self.jwt_id_ent.get().strip(), self.jwt_name_ent.get().strip(), self.jwt_email_ent.get().strip()
        secret = self.jwt_create_secret_ent.get().strip()
        if not secret: return
        payload = {"id": user_id, "name": name, "email": email, "iat": datetime.datetime.utcnow(), "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=60)}
        try:
            token = jwt.encode(payload, secret, algorithm="HS256")
            if isinstance(token, bytes): token = token.decode('utf-8')
            self.jwt_gen_token.delete('1.0', tk.END)
            self.jwt_gen_token.insert('1.0', token)
            self.jwt_verify_token_ent.delete('1.0', tk.END)
            self.jwt_verify_token_ent.insert('1.0', token)
            self.set_status("JWT Generated")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def verify_jwt(self):
        token = self.jwt_verify_token_ent.get('1.0', 'end-1c').strip()
        secret = self.jwt_verify_secret_ent.get().strip()
        if not token or not secret: return
        self.jwt_result_area.configure(state='normal')
        self.jwt_result_area.delete('1.0', tk.END)
        try:
            decoded_data = jwt.decode(token, secret, algorithms=["HS256"])
            result_text = f"✅ Valid Signature!\n\nFull Payload:\n{json.dumps(decoded_data, indent=2)}"
            self.jwt_result_area.insert('1.0', result_text)
            self.jwt_result_area.configure(text_color="#4ade80")
            self.set_status("JWT Verified")
        except Exception as e:
            self.jwt_result_area.insert('1.0', f"❌ Error: {str(e)}")
            self.jwt_result_area.configure(text_color="#f87171")
        self.jwt_result_area.configure(state='disabled')

    def show_explanation_view(self):
        for widget in self.main_container.winfo_children():
            widget.destroy()
        self.create_header(self.main_container, "Explanation")
        self.exp_nav_frame = ctk.CTkScrollableFrame(self.main_container, height=60, orientation="horizontal", fg_color="transparent", bg_color="transparent")
        self.exp_nav_frame.pack(fill='x', padx=20, pady=(10, 0))
        
        self.exp_content_frame = ctk.CTkFrame(self.main_container, fg_color=self.bg_color, border_width=1, border_color=self.cyan_accent, corner_radius=10)
        self.exp_content_frame.pack(fill='both', expand=True, padx=20, pady=(10, 20))
        
        self.exp_frames = {}
        self.exp_buttons = {}
        
        def select_exp_tab(name):
            for btn_name, btn in self.exp_buttons.items():
                if btn_name == name:
                    btn.configure(fg_color=self.cyan_accent, text_color="#000000", border_color=self.cyan_accent)
                else:
                    btn.configure(fg_color=self.frame_bg, text_color=self.cyan_accent, border_color="#1e293b")
            
            for frame_name, frame in self.exp_frames.items():
                if frame_name == name:
                    frame.pack(fill='both', expand=True, padx=5, pady=5)
                else:
                    frame.pack_forget()
                    
        algorithms = [("Base64", "base64.png"), ("Caesar Cipher", "caesar.png"), ("Multiplicative Cipher", "multiplicative.png"), ("Vigenère Cipher", "vigenere.png"), ("Rail Fence Cipher", "railfence.png"), ("Columnar Transposition Cipher", "transposition.png"), ("Simple Substitution Cipher", "substitution.png"), ("XOR Cipher", "xor.png"), ("JWT", "structure of JWT.webp"), ("ECC", "ecc.png")]
        
        for name, img_file in algorithms:
            btn = ctk.CTkButton(self.exp_nav_frame, text=name.split(" ")[0].upper(), font=('Consolas', 13, 'bold'), 
                                corner_radius=20, border_width=1, height=40, hover_color="#0284c7",
                                command=lambda n=name: select_exp_tab(n))
            btn.pack(side='left', padx=5, pady=5)
            self.exp_buttons[name] = btn
            
            frame = ctk.CTkFrame(self.exp_content_frame, fg_color="transparent")
            self.exp_frames[name] = frame
            self.create_explain_tab(frame, name, img_file)
            
        if algorithms:
            select_exp_tab(algorithms[0][0])

    def create_explain_tab(self, parent, name, img_file):
        parent.grid_columnconfigure((0, 1), weight=1)
        parent.grid_rowconfigure(0, weight=1)
        frame_kwargs = {"fg_color": self.frame_bg, "corner_radius": 10, "border_width": 1, "border_color": self.cyan_accent}
        text_frame = ctk.CTkFrame(parent, **frame_kwargs)
        text_frame.grid(row=0, column=0, padx=(0, 5), pady=5, sticky="nsew")
        txt_widget = ctk.CTkTextbox(text_frame, fg_color="#030712", text_color=self.text_color, font=('Consolas', 13), wrap='word')
        txt_widget.pack(fill='both', expand=True, padx=15, pady=15)
        txt_widget.insert(tk.END, self.explanations.get(name, "Explanation not found."))
        txt_widget.configure(state='disabled')
        img_frame = ctk.CTkFrame(parent, **frame_kwargs)
        img_frame.grid(row=0, column=1, padx=(5, 0), pady=5, sticky="nsew")
        try:
            img_path = os.path.join(os.path.dirname(__file__), 'Summaries', 'images', img_file)
            if os.path.exists(img_path):
                img = Image.open(img_path)
                max_size = 550
                ratio = min(max_size / max(1, img.width), max_size / max(1, img.height))
                new_size = (int(img.width * ratio), int(img.height * ratio))
                ctk_img = ctk.CTkImage(light_image=img, dark_image=img, size=new_size)
                ctk.CTkLabel(img_frame, image=ctk_img, text="").pack(expand=True)
        except: pass

    def create_ecc_tab(self, parent):
        parent.grid_columnconfigure((0, 1, 2), weight=1)
        parent.grid_rowconfigure(0, weight=1)
        
        frame_kwargs = {"fg_color": self.frame_bg, "corner_radius": 10, "border_width": 1, "border_color": self.cyan_accent}
        
        # ALICE FRAME (Left)
        alice_frame = ctk.CTkFrame(parent, **frame_kwargs)
        alice_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        ctk.CTkLabel(alice_frame, text="■ ALICE (USER A)", font=('Consolas', 14, 'bold'), text_color=self.cyan_accent).pack(anchor='w', padx=15, pady=(15, 5))
        
        btn_alice = ctk.CTkButton(alice_frame, text="GENERATE ALICE KEYS", font=('Consolas', 12, 'bold'), fg_color="#10b981", hover_color="#059669", text_color="#000000")
        btn_alice.pack(fill='x', padx=15, pady=(5, 10))
        
        ctk.CTkLabel(alice_frame, text="Private Key (Ka):", text_color="#94a3b8", font=('Consolas', 11)).pack(anchor='w', padx=15)
        a_priv = ctk.CTkTextbox(alice_frame, fg_color="#030712", text_color=self.text_color, font=('Consolas', 12), height=60, border_width=1, border_color="#1e293b", corner_radius=5)
        a_priv.pack(fill='x', padx=15, pady=(0, 10))
        
        ctk.CTkLabel(alice_frame, text="Public Key (X):", text_color="#94a3b8", font=('Consolas', 11)).pack(anchor='w', padx=15)
        a_pub = ctk.CTkTextbox(alice_frame, fg_color="#030712", text_color=self.text_color, font=('Consolas', 12), height=100, border_width=1, border_color="#1e293b", corner_radius=5)
        a_pub.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        
        # BOB FRAME (Right)
        bob_frame = ctk.CTkFrame(parent, **frame_kwargs)
        bob_frame.grid(row=0, column=2, padx=10, pady=10, sticky="nsew")
        ctk.CTkLabel(bob_frame, text="■ BOB (USER B)", font=('Consolas', 14, 'bold'), text_color=self.cyan_accent).pack(anchor='w', padx=15, pady=(15, 5))
        
        btn_bob = ctk.CTkButton(bob_frame, text="GENERATE BOB KEYS", font=('Consolas', 12, 'bold'), fg_color="#10b981", hover_color="#059669", text_color="#000000")
        btn_bob.pack(fill='x', padx=15, pady=(5, 10))
        
        ctk.CTkLabel(bob_frame, text="Private Key (Kb):", text_color="#94a3b8", font=('Consolas', 11)).pack(anchor='w', padx=15)
        b_priv = ctk.CTkTextbox(bob_frame, fg_color="#030712", text_color=self.text_color, font=('Consolas', 12), height=60, border_width=1, border_color="#1e293b", corner_radius=5)
        b_priv.pack(fill='x', padx=15, pady=(0, 10))
        
        ctk.CTkLabel(bob_frame, text="Public Key (Y):", text_color="#94a3b8", font=('Consolas', 11)).pack(anchor='w', padx=15)
        b_pub = ctk.CTkTextbox(bob_frame, fg_color="#030712", text_color=self.text_color, font=('Consolas', 12), height=100, border_width=1, border_color="#1e293b", corner_radius=5)
        b_pub.pack(fill='both', expand=True, padx=15, pady=(0, 15))

        # EXCHANGE FRAME (Center)
        center_frame = ctk.CTkFrame(parent, fg_color="transparent")
        center_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        
        exchange_box = ctk.CTkFrame(center_frame, **frame_kwargs)
        exchange_box.pack(fill='both', expand=True)
        ctk.CTkLabel(exchange_box, text="■ KEY EXCHANGE (ECDH)", font=('Consolas', 14, 'bold'), text_color=self.cyan_accent).pack(anchor='w', padx=15, pady=(15, 5))
        
        btn_exchange = ctk.CTkButton(exchange_box, text="COMPUTE SHARED SECRET", font=('Consolas', 13, 'bold'), fg_color=self.cyan_accent, hover_color="#0ea5e9", text_color="#000000")
        btn_exchange.pack(fill='x', padx=15, pady=(15, 15))
        
        ctk.CTkLabel(exchange_box, text="Shared Secret (Alice):", text_color="#94a3b8", font=('Consolas', 11)).pack(anchor='w', padx=15)
        a_secret = ctk.CTkTextbox(exchange_box, fg_color="#030712", text_color=self.text_color, font=('Consolas', 12), height=60, border_width=1, border_color="#1e293b", corner_radius=5)
        a_secret.pack(fill='x', padx=15, pady=(0, 10))
        
        ctk.CTkLabel(exchange_box, text="Shared Secret (Bob):", text_color="#94a3b8", font=('Consolas', 11)).pack(anchor='w', padx=15)
        b_secret = ctk.CTkTextbox(exchange_box, fg_color="#030712", text_color=self.text_color, font=('Consolas', 12), height=60, border_width=1, border_color="#1e293b", corner_radius=5)
        b_secret.pack(fill='x', padx=15, pady=(0, 15))

        # ECC LOGIC
        state = {"Ka": None, "X": None, "Kb": None, "Y": None, "curve": None}
        
        def compress(pubKey):
            return hex(pubKey.x) + hex(pubKey.y % 2)[2:]
            
        def gen_alice():
            try:
                from tinyec import registry
                import secrets
                if state["curve"] is None: state["curve"] = registry.get_curve('brainpoolP256r1')
                state["Ka"] = secrets.randbelow(state["curve"].field.n)
                state["X"] = state["Ka"] * state["curve"].g
                
                a_priv.delete("1.0", tk.END)
                a_priv.insert(tk.END, hex(state["Ka"]))
                a_pub.delete("1.0", tk.END)
                a_pub.insert(tk.END, compress(state["X"]))
                self.status_var.set("Alice keys generated | Mode: Active | Security Level: High")
            except Exception as e:
                messagebox.showerror("Error", str(e))
                
        def gen_bob():
            try:
                from tinyec import registry
                import secrets
                if state["curve"] is None: state["curve"] = registry.get_curve('brainpoolP256r1')
                state["Kb"] = secrets.randbelow(state["curve"].field.n)
                state["Y"] = state["Kb"] * state["curve"].g
                
                b_priv.delete("1.0", tk.END)
                b_priv.insert(tk.END, hex(state["Kb"]))
                b_pub.delete("1.0", tk.END)
                b_pub.insert(tk.END, compress(state["Y"]))
                self.status_var.set("Bob keys generated | Mode: Active | Security Level: High")
            except Exception as e:
                messagebox.showerror("Error", str(e))
                
        def compute_exchange():
            if state["Ka"] is None or state["Kb"] is None:
                messagebox.showerror("Error", "Both Alice and Bob must generate keys first!")
                return
            try:
                a_shared = state["Ka"] * state["Y"]
                b_shared = state["Kb"] * state["X"]
                
                a_secret.delete("1.0", tk.END)
                a_secret.insert(tk.END, compress(a_shared))
                b_secret.delete("1.0", tk.END)
                b_secret.insert(tk.END, compress(b_shared))
                
                if compress(a_shared) == compress(b_shared):
                    self.status_var.set("Shared secrets match successfully! | Mode: Active | Security Level: High")
            except Exception as e:
                messagebox.showerror("Error", str(e))
                
        btn_alice.configure(command=gen_alice)
        btn_bob.configure(command=gen_bob)
        btn_exchange.configure(command=compute_exchange)

if __name__ == "__main__":
    app = ctk.CTk()
    toolkit = CryptoToolkit(app)
    app.mainloop()
