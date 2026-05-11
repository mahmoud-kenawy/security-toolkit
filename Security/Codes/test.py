hex = input("enter hex key")
bin_hex = bin(int(hex),16)[2:].zfill(64)
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
prem_key = "".join(bin_hex[i-1] for i in PC1)
L = prem_key[:28]
R = prem_key[28:]

def letf_shift(bits,n):
    return bits[n:]+bits[:n]

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
ROTATIONS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

for i in PC2:
    L = letf_shift(L,ROTATIONS[i])
    R = letf_shift(R,ROTATIONS[i])
    combined = L+R
    prem_key2 = "".join(combined[j-1] for j in PC2)

def permute(bits,pattern):
    return "".join(bits[i-1] for i in pattern)

def left_shift(bits,n):
    return bits[n:]+bits[:n]

def generate_key(key):
    P10 = [3,5,2,7,4,10,1,9,8,6]
    P8  = [6,3,7,4,8,5,10,9]
    k = permute(key,P10)
    left , right = key[5:],key[:5]
    left , right = left_shift(left,1) , left_shift(right,1)
    k1 = permute(left+right,P8)
    left , right = left_shift(left,2) , left_shift(right,2)
    k2 = permute(left+right,P8)
    return k1,k2
def fk(bits,key):
    pass
def encrypt(plaintext,key):
    IP = [2,6,3,1,4,8,5,7]
    IP_inv = [4,1,3,5,7,2,8,6]
    k1,k2 = generate_key(key)
    
    bits = permute(k1,IP)
    #round 1
    bits = fk(bits,IP)
    #swap halves
    bits = bits[4:]+bits[:4]

    bits = fk(bits,IP_inv)

    ct = permute(bits,IP_inv)


