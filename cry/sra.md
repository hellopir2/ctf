### SRA
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
