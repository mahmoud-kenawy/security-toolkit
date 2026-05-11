"""
TranspositionCipherDecrypt.py
Decryption for Columnar Transposition Cipher.
Reconstructs the columns from the ciphertext using the original key order,
then reads them row-by-row to recover the plaintext.
"""

import math


def decode(key, ciphertext):
    num_cols = len(key)
    num_rows = math.ceil(len(ciphertext) / num_cols)

    # Columns whose index >= (len % num_cols) are one character shorter
    last_row_len = len(ciphertext) % num_cols
    short_cols = set(range(last_row_len, num_cols)) if last_row_len != 0 else set()

    # Build the same order mapping as the encoder
    order = {int(val): num for num, val in enumerate(key)}
    sorted_keys = sorted(order.keys())

    # Split ciphertext back into columns (in the same sorted-key order used during encoding)
    col_data = {}
    idx = 0
    for k in sorted_keys:
        col_pos = order[k]
        length = num_rows - 1 if col_pos in short_cols else num_rows
        col_data[col_pos] = ciphertext[idx:idx + length]
        idx += length

    # Reconstruct plaintext by reading row by row across all columns
    plaintext = ''
    for row in range(num_rows):
        for col in range(num_cols):
            if row < len(col_data[col]):
                plaintext += col_data[col][row]
    return plaintext


if __name__ == '__main__':
    key        = '1320'
    ciphertext = 'LOHORLWDE L'   # encoded "HELLO WORLD"
    print("Cipher   :", ciphertext)
    print("Decrypted:", decode(key, ciphertext))
