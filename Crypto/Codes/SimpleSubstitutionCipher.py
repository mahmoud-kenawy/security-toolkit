LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
text = 'hello'
key = 'POIUYTRWEQASDFGHJKLMNBVCXZ'
translated = ''
charsA = LETTERS
charsB = key
for symbol in text:
    if symbol.upper() in charsA:
        symIndex = charsA.find(symbol.upper())
        if symbol.isupper():
            translated += charsB[symIndex].upper()
        else:
            translated += charsB[symIndex].lower()
    else:
        translated += symbol
print(translated)