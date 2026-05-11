# 💎 Cyber-Premium Crypto Toolkit

A modern, high-performance desktop application built with `CustomTkinter` that provides interactive encryption, decryption, and educational explanations for 10 distinct cryptographic algorithms. Designed with a sleek "cyber-premium" dark theme, this tool is perfect for learning cryptography, testing security algorithms, and exploring secure data transmission.

## ✨ Features

- **10 Cryptographic Algorithms:** 
  - **Encoding:** Base64
  - **Classic Ciphers:** Caesar, Multiplicative, Simple Substitution, Vigenère
  - **Transposition:** Rail Fence, Columnar Transposition
  - **Modern / Logical:** XOR Cipher
  - **Web Security:** JWT (JSON Web Tokens) with automatic timestamp handling
  - **Advanced Key Exchange:** ECC (Elliptic Curve Diffie-Hellman using `brainpoolP256r1`)
- **Strict Input Validation:** Robust error handling prevents crashes by enforcing cryptographic rules (e.g., coprime keys for Multiplicative cipher, 1-25 shifts for Caesar, minimum rails for Rail Fence).
- **Educational Explanations:** A dedicated "Explanations" tab provides detailed text summaries and visual diagrams for every single algorithm.
- **Dynamic Cyber UI:** Custom-built pill-navigation system, neon cyan accents, and real-time status bars.

## 🛠 Prerequisites

Ensure you have Python 3.8+ installed. You will need the following Python libraries to run the toolkit:

```bash
pip install customtkinter Pillow PyJWT tinyec
```

## 🚀 How to Run

Navigate to the project directory and run the main application file:

```bash
python crypto_toolkit.py
```

## 📂 Project Structure

- `crypto_toolkit.py`: The main application file containing the `CustomTkinter` UI, algorithm logic (`CryptoEngine`), and error handling.
- `Summaries/`: Contains text files (`.txt`) with educational explanations for each algorithm.
  - `images/`: Contains high-quality, modern cyber-security diagrams (`.png`, `.webp`) used in the Explanations tab.
- `Codes/`: Contains the original standalone scripts and math logic for individual algorithms (such as the base `ecc.py` logic).

## 💡 Usage Guide

1. **Codes Tab:** Select an algorithm from the top navigation bar. Enter your Plaintext and Key (if applicable), then click **ENCRYPT** or **DECRYPT**.
2. **Explanations Tab:** Click on the "Explanations" view at the top of the screen to read how the underlying math works for the currently selected algorithm.
3. **ECC Key Exchange:** The ECC tab features a specialized 3-column layout where you can generate public/private key pairs for "Alice" and "Bob", and calculate the resulting shared secret.

## 🔒 Security Note
While this toolkit accurately demonstrates the mathematical principles behind these algorithms, it is built for **educational purposes**. Classic ciphers (Caesar, Vigenère, etc.) are easily broken using frequency analysis and should not be used to protect sensitive real-world data.
