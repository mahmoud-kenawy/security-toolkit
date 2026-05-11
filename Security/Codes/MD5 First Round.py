import math

def padding_md5(msg):
    
    msg_bytes = bytearray(msg.encode('utf-8'))
    msg_len_bits = len(msg_bytes) * 8 
    blocks=math.floor(msg_len_bits/512)
    len_block=msg_len_bits-(blocks*512)
    if len_block<448:
        pad=512-(len_block+64)
    else:
        pad=(512-(len_block+64))+512
    return pad

s1=[7,12,17,22]
t=[
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821
]
def first_round(a, b, c, d, k, i):
    f = (b & c) | (~b & d)
    f = (f + a + t[i] + k) & 0xFFFFFFFF
    f = (f << s1[i % 4]) | (f >> (32 - s1[i % 4]))
    f = (f + b) & 0xFFFFFFFF
    return f

print(padding_md5("security"))

