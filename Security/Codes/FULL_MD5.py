import math
import struct

def left_rotate(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def md5(message):
    # Step 1: Padding
    msg_bytes = bytearray(message.encode('utf-8'))
    orig_len_bits = len(msg_bytes) * 8
    msg_bytes.append(0x80)  # add 1 bit then zeros
    while (len(msg_bytes) * 8) % 512 != 448:
        msg_bytes.append(0x00)
    
    # Append original length in bits as 64-bit little-endian
    msg_bytes += struct.pack('<Q', orig_len_bits)
    
    # Step 2: Initialize buffers
    a0 = 0x67452301
    b0 = 0xEFCDAB89
    c0 = 0x98BADCFE
    d0 = 0x10325476
    
    # Shift amounts per round
    s = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    ]
    
    # Constants T[i] for MD5
    K = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    ]
    
    # Step 3: Process each 512-bit block
    for i in range(0, len(msg_bytes), 64):
        block = msg_bytes[i:i+64]
        
        # Break block into 16 words (32-bit each)
        M = list(struct.unpack('<16I', block))
        
        # Initialize hash for this block
        A = a0
        B = b0
        C = c0
        D = d0
        
        # Step 4: Process in 4 rounds (64 operations)
        for j in range(64):
            if 0 <= j <= 15:
                F = (B & C) | ((~B) & D)
                g = j
            elif 16 <= j <= 31:
                F = (D & B) | ((~D) & C)
                g = (5*j + 1) % 16
            elif 32 <= j <= 47:
                F = B ^ C ^ D
                g = (3*j + 5) % 16
            else:  # 48 to 63
                F = C ^ (B | (~D))
                g = (7*j) % 16
            
            # Perform the operation
            F = (F + A + K[j] + M[g]) & 0xFFFFFFFF
            A = D
            D = C
            C = B
            B = (B + left_rotate(F, s[j])) & 0xFFFFFFFF
        
        # Add this block's hash to result
        a0 = (a0 + A) & 0xFFFFFFFF
        b0 = (b0 + B) & 0xFFFFFFFF
        c0 = (c0 + C) & 0xFFFFFFFF
        d0 = (d0 + D) & 0xFFFFFFFF
    
    # Step 5: Output final hash as 128-bit digest
    digest = struct.pack('<4I', a0, b0, c0, d0)
    return digest.hex()

# Example usage
if __name__ == "__main__":
    message = "security"  #ِADD THE INPUT HERE <3
    hashed = md5(message)
    print(f"Message: {message}")
    print(f"MD5 Hash: {hashed}")