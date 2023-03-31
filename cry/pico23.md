# SRA
In this challenge, we are given some code:
```py
from Crypto.Util.number import getPrime, inverse, bytes_to_long
from string import ascii_letters, digits
from random import choice

pride = "".join(choice(ascii_letters + digits) for _ in range(16))
gluttony = getPrime(128)
greed = getPrime(128)
lust = gluttony * greed
sloth = 65537
envy = inverse(sloth, (gluttony - 1) * (greed - 1))

anger = pow(bytes_to_long(pride.encode()), sloth, lust)

print(f"{anger = }")
print(f"{envy = }")

print("vainglory?")
vainglory = input("> ").strip()

if vainglory == pride:
    print("Conquered!")
    with open("/challenge/flag.txt") as f:
        print(f.read())
else:
    print("Hubris!")
```

The code above basically just performs the RSA algorithm, except the variable names are sins. I renamed the variables as such:
```py
from Crypto.Util.number import getPrime, inverse, bytes_to_long
from string import ascii_letters, digits
from random import choice

plaintext = "".join(choice(ascii_letters + digits) for _ in range(16))
p = getPrime(128)
q = getPrime(128)
n = p * q
e = 65537
d = inverse(e, (p - 1) * (q - 1))

ciphertext = pow(bytes_to_long(plaintext.encode()), e, n)

print(f"{ciphertext = }")
print(f"{d = }")

print("plaintext?")
plaintextinput = input("> ").strip()

if plaintextinput == plaintext:
    print("Conquered!")
    with open("/challenge/flag.txt") as f:
        print(f.read())
else:
    print("Hubris!")
```

Basically we just want to return the decrypted plaintext to them, after being given the private key and a ciphertext. We also know the exponent.

Using Euler's totient theorem (rsa moment), we can see that if d\*e is 1 mod phi(n) (definition of inverse), if we recover the public key, we can decrypt the plaintext.

So let's recover the public key. By definition, (d\*e)-1 is a multiple of phi(n), and since phi(n) is (p-1)(q-1), if we can factor phi(n), we could guess the factors that make up (p-1) and (q-1), and hopefully recover n, which is pq. Factoring phi(n) isn't that simple, but since simple factoring algorithms were too slow, I just moved my python code to sagemath and used the builtin is_prime() and factor() functions. Writing the code isn't too bad, although in my program you have to manually give an input and decode the output. The code is below:
```py
c = 2975001951034124260409018370089557409456117856707770671810591999146582022582 # manually input whatever the server gives
d = 32096147988071556010626580467850876675406881021250699619292883024800879557857 # manually input whatever the server gives
phi = (d * 65537) - 1
a = list(factor(phi))
for i in range(len(a)):
    a[i] = list(a[i])
    if a[i][1] > 1:
        while a[i][1] > 1:
            a.append(a[i][0])
            a[i][1] -= 1
    a[i] = a[i][0]
p = 1
q = 1
flag = False
for i in range(2^len(a)):
    b = []
    cc = bin(i)
    cc = cc[2:len(cc)]
    cc = "0"*(len(a) - len(cc)) + cc
    p = 1
    for j in range(len(a)):
        if cc[j] == "1":
            p *= a[j]
        if cc[j] == "0":
            b.append(a[j])
    p += 1
    #print(cc)
    if len(bin(p)) > 128 and len(bin(p)) < 131 and is_prime(p):
        for j in range(2^len(b)):
            ccc = bin(j)
            ccc = ccc[2:len(ccc)]
            ccc = "0"*(len(b) - len(ccc)) + ccc
            q = 1
            for k in range(len(b)):
                if ccc[k] == "1":
                    q *= b[k]
            q += 1
            if len(bin(q)) > 125 and len(bin(q)) < 135 and is_prime(q):
                print(p, q)
                flag = True
                break
    if flag:
        break
print(pow(c, d, p*q))
```

After writing this code, I noticed it was a bit slow, and that it sometimes had bad outputs.<br>
But, it still works at least half the time. So using this code, I got the flag: `picoCTF{7h053_51n5_4r3_n0_m0r3_2b7ad1ae}`

But I also decided to improve my code:

```py
import codecs
c = 11674297585730485944977782475730972213156960142908616463139668275892428061104
d = 74542128819600721176203930879599480846248455200594374918238026115775280129953
phi = (d * 65537) - 1
lists = []
a = list(factor(phi))
for i in range(len(a)):
    a[i] = list(a[i])
    if a[i][1] > 1:
        while a[i][1] > 1:
            a.append(a[i][0])
            a[i][1] -= 1
    a[i] = a[i][0]
a.sort()
a.pop(0)
a.pop(0)
a.reverse()
vari = 2
var = 2
if a[0] * a[1] > 2^128:
    vari *= a[0]
    var *= a[1]
    a.pop(0)
    a.pop(0)
p = vari
q = var
flag = False
for i in range(2^len(a)):
    b = []
    cc = bin(i)
    cc = cc[2:len(cc)]
    cc = "0"*(len(a) - len(cc)) + cc
    p = vari
    for j in range(len(a)):
        if cc[j] == "1":
            p *= a[j]
        if cc[j] == "0":
            b.append(a[j])
    p += 1
    #print(cc)
    if len(bin(p)) > 128 and len(bin(p)) < 131 and is_prime(p):
        for j in range(2^len(b)):
            ccc = bin(j)
            ccc = ccc[2:len(ccc)]
            ccc = "0"*(len(b) - len(ccc)) + ccc
            q = var
            for k in range(len(b)):
                if ccc[k] == "1":
                    q *= b[k]
            q += 1
            if len(bin(q)) > 128 and len(bin(q)) < 131 and is_prime(q):
                #print(p, q)
                lists.append([p, q])
                try:
                    x = pow(c, d, p*q)
                    print(codecs.decode(hex(x)[2:len(hex(x))], "hex").decode())
                except:
                    continue
                else:
                    flag = True
            if flag:
                break
    if flag:
        break
```

This code is still really slow sometimes. I hypothesized it was because I went and sequentially checked the factors, so I just made the factor checking random. This actually made it quite a lot faster. I also added a timer so I could track how fast it was :)

```py
import codecs
import time
import random
start_time = time.time()
c = 39252196840070819574591101432097316542218234444874418585805025260835928836911
d = 32987666344061558038392041477220255851545178713851033675230784821525279216993
phi = (d * 65537) - 1
a = list(factor(phi))
for i in range(len(a)):
    a[i] = list(a[i])
    if a[i][1] > 1:
        while a[i][1] > 1:
            a.append(a[i][0])
            a[i][1] -= 1
    a[i] = a[i][0]
a.sort()
a.pop(0)
a.pop(0)
#a.reverse()
p = 2
q = 2
flag = False
print(e := len(a))
while True:
    i = random.randint(1, 2^e)
    b = []
    pprimes = bin(i)
    f = len(pprimes)
    pprimes = pprimes[2:f]
    pprimes = "0"*(e - f + 2) + pprimes
    p = 2
    for j in range(e):
        if pprimes[j] == "1":
            p *= a[j]
        if pprimes[j] == "0":
            b.append(a[j])
    p += 1
    #print(pprimes)
    if len(bin(p)) == 130 and is_prime(p):
        g = len(b)
        for j in range(2^g):
            #j = random.randint(1, 2^len(b))
            qprimes = bin(j)
            h = len(qprimes)
            qprimes = qprimes[2:h]
            qprimes = "0"*(g - h + 2) + qprimes
            q = 2
            for k in range(g):
                if qprimes[k] == "1":
                    q *= b[k]
            q += 1
            if len(bin(q)) == 130 and is_prime(q):
                #print(p, q)
                try:
                    x = pow(c, d, p*q)
                    y = hex(x)
                    print(codecs.decode(y[2:len(y)], "hex").decode())
                except:
                    continue
                else:
                    flag = True
            if flag:
                break
    if flag:
        break
print("%s seconds" % round((time.time() - start_time), 1))
```

I don't know how to optimize this further so I'll just leave it here.

# PowerAnalysis: Part 1

I read the challenge and was like, "surely there are some implementations of an AES powertrace side channel attack online". And yeah. There are. After digging around a bit, I found this implementation of CPA online: https://github.com/nvietsang/dpa-on-aes/blob/master/main_cpa.py

So, let's take this code and modify it to suit our own purposes. Since we're given plaintext instead of ciphertext, I looked through the code to check if there was anything that had to be changed. Surprisingly, the only thing that needed to be changed was the inverted sbox, since I don't need to invert sbox for plaintext encryption.

Aside from this, I just generated random plaintexts and queried the server for the traces, and commented out a few unnecessary lines. The final modified code is below:

```py
from os import listdir, path
from matplotlib import pyplot as plt
import random
import numpy as np
from pwn import *
B16 = 16
B256 = 256
B8 = 8
N = 100
T = 2666
SIZE = 32

# INPUT = 'all_plaintext.txt'
# FOLDER = 'traces'

sbox = [
   0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
   0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
   0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
   0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
   0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
   0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
   0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
   0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
   0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
   0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
   0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
   0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
   0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
   0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
   0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
   0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

inv_sbox = [
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
]
# hamming weights for CPA
HW = [bin(n).count("1") for n in range(0, 256)]

assert len(sbox) == B16*B16
assert len(inv_sbox) == B16*B16

# f = open(INPUT, 'r')
# data = f.read()
# ciphertext = data.split('\n')
# ciphertext = [c for c in ciphertext if c != '']



def apply_sbox(idx):
	return sbox[idx]

def apply_inv_sbox(idx):
	return inv_sbox[idx]

# print(ciphertext[0])

trace = []
ciphertext = []
for i in range(100):
    io = remote('saturn.picoctf.net', 60682) # get your own port or something
    print(io.recv())
    abcd = str(hex(random.randint(0, 2**128)))
    abcd = abcd[2:len(abcd)]
    abcd = "0" * (32 - len(abcd)) + abcd
    print(abcd)
    print(len(abcd))
    ciphertext.append(abcd)
    abcd = abcd + "\n"
    io.send(abcd.encode())
    data = io.recvline().strip().decode().strip()
    #print(data)
    data = data[28:-1]
    data = data.split(', ')
    for i in range(len(data)):
      data[i] = int(data[i])
    assert len(data) == T
    trace.append(data)
trace = np.array(trace)
assert len(trace) == N

for i, c in enumerate(ciphertext):
	ci = []
	for j in range(int(SIZE/2)):
		bci = c[j*2: j*2+2] # each byte in c
		bci = '0x'+bci
		bci = int(bci, B16)
		ci.append(bci)
	ciphertext[i] = ci
#print(ciphertext)
key = []

for byte_index in range(B16):
	cpa_output = [0]*B256
	max_cpa = [0]*B256

	for key_guess in range(B256):
		#print('Byte {} - Guess {} - Key: {}'.format(byte_index, key_guess, key))
		power_mode = np.zeros(N)
		numerator = np.zeros(T)
		denominator_model = np.zeros(T)
		denominator_measured = np.zeros(T)

		for trace_index in range(N):
			vij = apply_sbox(ciphertext[trace_index][byte_index] ^ key_guess) #plaintext is named ciphertext, so sbox is used instead of inv_sbox
			power_mode[trace_index] = HW[vij] #i removed the ^250 because i don't know what it's supposed to do

		mean_h = np.mean(power_mode)
		mean_t = np.mean(trace, axis=0)
    # standard deviation calculations
		for trace_index in range(N):
			# h - h_bar
			h_diff = power_mode[trace_index] - mean_h
			# t - t_bar
			t_diff = trace[trace_index][:] - mean_t
			# (h - h_bar)(t - t_bar)
			numerator += h_diff * t_diff
			# (h - h_bar)^2
			denominator_model += h_diff ** 2
			# (t - t_bar)^2
			denominator_measured += t_diff ** 2
		cpa_output[key_guess] = numerator / np.sqrt(denominator_model*denominator_measured)
		max_cpa[key_guess] = max(abs(cpa_output[key_guess]))	
	key.append(np.argmax(max_cpa))
	# print(cpa_output[6])

print(key)
```

As with the SRA code, you need to manually turn the key into hex, but this isn't that hard because you can just plug it into rapidtables. After 1 failed attempt of getting unlucky on the last byte, I got the flag.
