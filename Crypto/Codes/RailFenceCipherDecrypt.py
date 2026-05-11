"""
RailFenceCipherDecrypt.py
Decryption for Rail Fence Cipher.
Reconstructs the zigzag pattern, fills rails with ciphertext characters,
then reads them back in the original left-to-right order.
"""

def decrypt(ciphertext, key):
    if key < 2:
        return ciphertext

    n = len(ciphertext)

    # Step 1: Build the zigzag rail pattern (which rail each position belongs to)
    pattern = []
    rail = 0
    direction = 1
    for _ in range(n):
        pattern.append(rail)
        if rail == 0:
            direction = 1
        elif rail == key - 1:
            direction = -1
        rail += direction

    # Step 2: Sort original positions by (rail index, position)
    #         This tells us the order in which characters were placed in the cipher
    indices = sorted(range(n), key=lambda i: (pattern[i], i))

    # Step 3: Map ciphertext characters back to their original positions
    result = [''] * n
    for cipher_idx, plain_idx in enumerate(indices):
        result[plain_idx] = ciphertext[cipher_idx]

    return ''.join(result)


if __name__ == '__main__':
    cipher = "WECRLTEERDSOEEFEAABORADICVNE"  # "WEAREDISCOVEREDRUNATONCE" with 3 rails
    key = 3
    print("Cipher   :", cipher)
    print("Decrypted:", decrypt(cipher, key))
