# Crypto Toolkit — Final Implementation Plan

## Overview

Build `d:\My\Project\SC\Crypto\crypto_toolkit.py`, a premium Tkinter desktop app  
using the **8 classical cipher algorithms** already in `Crypto\Codes\`.  
Same structure concept as `security_toolkit.py` (landing → Codes or Explanation),  
but with completely new algorithms, enhanced UI, and a new `Summaries\` folder.

---

## Final Project Structure

```
d:\My\Project\SC\Crypto\
│
├── crypto_toolkit.py                     ← [NEW] Main application
│
├── Codes\                                ← [EXISTING + UPDATED]
│   ├── Base64.py                         │  original (encode + decode already)
│   ├── CaserCipher.py                    │  original (encrypt only)
│   ├── CaserCipherDecrypt.py             │  new decrypt file ✓
│   ├── MultiplicativeCipher.py           │  original (encrypt only)
│   ├── MultiplicativeCipherDecrypt.py    │  new decrypt file ✓
│   ├── RailFenceCipher.py                │  original (encrypt only)
│   ├── RailFenceCipherDecrypt.py         │  new decrypt file ✓
│   ├── SimpleSubstitutionCipher.py       │  original (encrypt only)
│   ├── SimpleSubstitutionCipherDecrypt.py│  new decrypt file ✓
│   ├── TranspositionCipher.py            │  original (encrypt only)
│   ├── TranspositionCipherDecrypt.py     │  new decrypt file ✓
│   ├── VignereCipher.py                  │  original (encrypt only)
│   ├── VignereCipherDecrypt.py           │  new decrypt file ✓
│   └── XORalgorithm.py                   ← original (symmetric, no separate decrypt needed)
│
└── Summaries\                            ← [NEW]
    ├── 1.txt                             │  Base64 + Caesar explanations
    ├── 2.txt                             │  Multiplicative + Vigenère explanations
    ├── 3.txt                             │  Rail Fence + Transposition + Substitution
    ├── 4.txt                             │  XOR explanation
    └── images\
        ├── base64.png
        ├── caesar.png
        ├── multiplicative.png
        ├── railfence.png
        ├── substitution.png
        ├── transposition.png
        ├── vigenere.png
        └── xor.png
```

---

## Algorithm Tabs (8 total)

| # | Tab Name | Encrypt Source | Decrypt Source | Inputs from User |
|---|---|---|---|---|
| 1 | 📦 Base64 | `Base64.py` | same file (b64decode) | `Text` |
| 2 | 🔡 Caesar | `CaserCipher.py` | `CaserCipherDecrypt.py` | `Plaintext`, `Shift (1–25)` |
| 3 | ✖️ Multiplicative | `MultiplicativeCipher.py` | `MultiplicativeCipherDecrypt.py` | `Plaintext`, `Key (coprime to 26)` |
| 4 | 🚂 Rail Fence | `RailFenceCipher.py` | `RailFenceCipherDecrypt.py` | `Plaintext`, `Number of Rails` |
| 5 | 🔀 Substitution | `SimpleSubstitutionCipher.py` | `SimpleSubstitutionCipherDecrypt.py` | `Plaintext`, `Key Alphabet (26 chars)` |
| 6 | 🔲 Transposition | `TranspositionCipher.py` | `TranspositionCipherDecrypt.py` | `Plaintext`, `Column Key (digits)` |
| 7 | 🗝️ Vigenère | `VignereCipher.py` | `VignereCipherDecrypt.py` | `Plaintext`, `Keyword` |
| 8 | ⊕ XOR | `XORalgorithm.py` | same function (symmetric) | `Plaintext`, `XOR Key` |

> **Rule:** All input fields start **empty** with placeholder hints. No hardcoded defaults.
> Empty submission → validation warning popup, never a crash.

---

## Main App — `crypto_toolkit.py`

### Architecture
```
CryptoEngine          ← logic class: wraps all Codes\ functions cleanly
CryptoToolkit         ← UI class: builds and manages all windows/tabs
  ├── setup_styles()
  ├── create_landing_page()       ← animated glassmorphism landing
  ├── show_codes_view()           ← 8 algorithm tabs
  ├── show_explanation_view()     ← 8 explanation tabs (text + image)
  ├── load_explanations()         ← reads Summaries\ text files
  ├── create_<algo>_tab()         ← one method per algorithm
  ├── run_<algo>_encrypt()        ← encrypt handler per algorithm
  ├── run_<algo>_decrypt()        ← decrypt handler per algorithm
  └── utilities: copy, save, load file, status bar
```

### UI — Premium Dark Theme

**Color Palette**
| Token | Value | Usage |
|---|---|---|
| `BG_DEEP` | `#07090f` | Window background |
| `BG_CARD` | `#0f1623` | Card surfaces |
| `BG_FIELD` | `#131c2e` | Input fields |
| `ACCENT_GOLD` | `#f59e0b` | Buttons, active tabs, highlights |
| `ACCENT_CYAN` | `#22d3ee` | Output headers, secondary info |
| `ACCENT_RED` | `#f87171` | Encrypted output text |
| `ACCENT_GRN` | `#4ade80` | Decrypted output text |
| `TEXT_MAIN` | `#e2e8f0` | Body text |
| `TEXT_DIM` | `#475569` | Placeholder / hint labels |

**Key UI features**
- Window: `1050 × 750`, centered on screen, minimum size enforced
- **Landing page**: animated title fade-in, two large glassmorphism hero cards (CODES / EXPLANATION) with glow-on-hover
- **Tab bar**: custom pill tabs with gold underline indicator; back button returns to landing
- **Input cards**: dark frosted glass with `1px` gold top-border, styled entry fields with cyan left accent
- **Output cards**: dark boxes with built-in toolbar (📋 Copy | 💾 Save | 🗑 Clear)
- **Status bar**: animated footer showing last action + timestamp
- **Validation**: warning popup on empty/invalid fields

---

## Summaries Folder

### Text Files (4 files, English, practitioner tone)
Each covers: what it is · how it works · key parameters · strengths/weaknesses · real-world use.

| File | Algorithms Covered |
|---|---|
| `1.txt` | Base64 · Caesar Cipher |
| `2.txt` | Multiplicative Cipher · Vigenère Cipher |
| `3.txt` | Rail Fence · Columnar Transposition · Simple Substitution |
| `4.txt` | XOR Cipher |

### Images (8 AI-generated algorithm diagrams)
| File | Visualizes |
|---|---|
| `base64.png` | Base64 character table encoding flow |
| `caesar.png` | Alphabet wheel with shift visualization |
| `multiplicative.png` | Modular multiplication mapping A→Z |
| `railfence.png` | Zigzag grid with labeled rails |
| `substitution.png` | Plaintext → ciphertext alphabet table |
| `transposition.png` | Columnar grid with key-ordered columns |
| `vigenere.png` | Vigenère square tableau |
| `xor.png` | XOR truth table + byte-level example |

---

## Build Order

1. 🎨 Generate `Summaries\images\*.png` — 8 AI diagrams  
2. 📝 Write `Summaries\1.txt` → `4.txt` — explanation text files  
3. 🏗️ Build `crypto_toolkit.py`:
   - `CryptoEngine` class (logic wrappers for all Codes\ files)
   - `setup_styles()` and color system
   - Landing page with animation
   - Header + back navigation
   - 8 algorithm tabs (Codes view) — all inputs user-driven
   - 8 explanation tabs (Explanation view) with image loader
   - Status bar + Copy/Save/Load utilities
4. ✅ Verify all tabs and encrypt↔decrypt round-trips

---

## Verification

| Check | Expected Result |
|---|---|
| App launches | No import errors |
| Landing page | Animated title + two glow hero cards |
| CODES view | 8 tabs, all fields empty with hint placeholders |
| Each algorithm | Encrypt → output shown; Decrypt → original restored |
| Empty submit | Warning popup, no crash |
| Invalid key | Clear error message (e.g. key not coprime to 26) |
| EXPLANATION view | Text on left + diagram image on right per tab |
| Copy / Save / Load | All utility buttons functional |
| Back button | Returns to landing from both views |
| Status bar | Updates on every action with timestamp |

---

> [!IMPORTANT]
> **Pillow** is required for image display in the Explanation view.
> Install with: `pip install Pillow`
> If Pillow is not installed, the explanation tab gracefully shows text only (no crash).
