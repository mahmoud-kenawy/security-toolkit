def split_len(seq, length):
    ss=[]
    for i in range(0,len(seq),length):
        se=seq[i:i+length]
        ss.append(se)
        print(ss)
    return ss# [seq[i:i + length] for i in range(0, len(seq), length)]

def encode(key, plaintext):
    order = {
        int(val): num for num, val in enumerate(key)
    }
    #{4:0, 2:1, 1:2, 3:3}

    ciphertext = ''
    for index in sorted(order.keys()):
        for part in split_len(plaintext, len(key)):
            try:
                ciphertext += part[order[index]]
            except IndexError:
                continue

    return ciphertext
print("\n")
print(encode('1320', 'HELLO WORLD'))