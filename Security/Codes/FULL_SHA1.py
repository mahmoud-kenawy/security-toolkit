import struct

def left_rotate(n, b):
    """Left rotate n by b bits."""
    return ((n << b) | (n >> (32 - b))) & 0xffffffff

def sha1(message):
    
    
    # Step 1: Convert message to bytes
    if isinstance(message, str):
        data = bytearray(message, 'utf-8')
    else:
        data = bytearray(message)
    
    # Store original length in bits
    orig_len_bits = len(data) * 8
    
    # Step 2: Append padding
    # Append 1 bit (0x80) then zeros
    data.append(0x80)
    
    # Pad with zeros until length is 448 mod 512
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
        
        # Break chunk into 16 words (32-bit each)
        words = list(struct.unpack('>16I', chunk))
        
        # Step 6: Extend to 80 words
        for j in range(16, 80):
            # Formula: w[i] = left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)
            word = (words[j-3] ^ words[j-8] ^ words[j-14] ^ words[j-16])
            words.append(left_rotate(word, 1))
        
        # Initialize working variables
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        
        # Step 7: Main loop (80 operations)
        for j in range(80):
            if 0 <= j <= 19:
                # Round 1: f = (b & c) | ((~b) & d)
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= j <= 39:
                # Round 2: f = b ^ c ^ d
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= j <= 59:
                # Round 3: f = (b & c) | (b & d) | (c & d)
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:  # 60 <= j <= 79
                # Round 4: f = b ^ c ^ d
                f = b ^ c ^ d
                k = 0xCA62C1D6
            
            # Compute temp
            temp = (left_rotate(a, 5) + f + e + k + words[j]) & 0xffffffff
            
            # Update variables
            e = d
            d = c
            c = left_rotate(b, 30)
            b = a
            a = temp
        
        # Add this chunk's hash to result
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
    
    # Step 8: Produce final hash (160 bits)
    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)

# Main program
if __name__ == "__main__":
    # Get input from user
    message = input("Enter message to hash with SHA-1: ")
    
    # Calculate SHA-1 hash
    hashed = sha1(message)
    
    # Display result
    print(f"\nInput: '{message}'")
    print(f"SHA-1 Hash: {hashed}")
    print(f"Length: {len(hashed)} hex characters ({len(hashed)*4} bits)")