import string

LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]

def unshift(c, k):
    t1 = ALPHABET.index(c)
    t2 = ALPHABET.index(k)
    return ALPHABET[(t1 - t2) % len(ALPHABET)]

def b16_decode(encoded):
    plain = ""
    for i in range(0, len(encoded), 2):
        high = ALPHABET.index(encoded[i])
        low = ALPHABET.index(encoded[i + 1])
        binary = f"{high:04b}{low:04b}"
        plain += chr(int(binary, 2))
    return plain

def b16_encode(plain):
    enc = ""
    for c in plain:
        binary = "{0:08b}".format(ord(c))
        enc += ALPHABET[int(binary[:4], 2)]
        enc += ALPHABET[int(binary[4:], 2)]
    return enc


def shift(c, k):
    t1 = ord(c) - LOWERCASE_OFFSET
    t2 = ord(k) - LOWERCASE_OFFSET
    return ALPHABET[(t1 + t2) % len(ALPHABET)]

enc = "mlnklfnknljflfmhjimkmhjhmljhjomhmmjkjpmmjmjkjpjojgjmjpjojojnjojmmkmlmijimhjmmj"

for key in ALPHABET:
    try:
        b16 = "".join(unshift(c, key) for c in enc)
        decoded = b16_decode(b16)
        if "picoCTF" in decoded:
            print(f"[+] Key: {key} → Flag: {decoded}")
    except Exception:
        continue
flag = 'mlnklfnknljflfmhjimkmhjhmljhjomhmmjkjpmmjmjkjpjojgjmjpjojojnjojmmkmlmijimhjmmj'
key = ALPHABET
# assert all([k in ALPHABET for k in key])
# assert len(key) == 1

# b16 = b16_encode(flag)
# enc = ""
# for i, c in enumerate(b16):
#     enc += shift(c, key[i % len(key)])
# print(enc)


for k in key:
    msg = ""
    for m in flag:
        msg += shift(m, k)
        hexstr  = ""
        for l in msg:
            hexstr += hex(ALPHABET.find(l))[-1]
        s = ""
        for i in range(0, len(hexstr), 2):
            s += chr(int(hexstr[i:i+2], 16))
        if (len(s) == 39):
            print("key", k, "flag", s, "\n")
