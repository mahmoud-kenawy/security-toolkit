def encryptDecrypt(inpString):

    # Define XOR key
    # Any character value will work
    xorKey = 'pask;knword'

    # calculate length of input string
    length = len(inpString)
    inpSt=''
    k=0
    # perform XOR operation of key
    # with every character in string
    for i in range(length):

        inpSt = chr(ord(inpString[i]) ^ ord(xorKey[k]))
        print(inpSt, end = "")
        if k < len(xorKey):
            k=k+1
        else:
            k=0
    return inpString
if __name__ == '__main__':
    sampleString = "Hello world"

    # Encrypt the string
    print("Encrypted String: ")
    sampleString = encryptDecrypt(sampleString)