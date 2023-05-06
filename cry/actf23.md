# Millionaires

Solve script: (might add details later)
```py
from pwn import *
import os
import private_set_intersection.python as psi
import base64

io = remote("challs.actf.co", 32300)
print(io.recvuntil(b"proof of work: "))
print(y:=io.recvline().strip().decode())

x = os.popen(y).read().strip()
print(x)
print(io.recvuntil(b"solution: "))
io.sendline(x.encode())

def zero_encoding(x, n):
    ret = []

    s = bin(x)[2:].zfill(n)

    for i in range(n):
        if s[i] == "0":
            ret.append(s[:i] + "1")

    return ret



for i in range(10):
    print(io.recvline())
    c = psi.client.CreateWithNewKey(True)
    io.recvuntil(b"Size of client set: ")
    io.sendline(b"256")
    io.recvuntil(b"Setup:  ")
    setup = psi.ServerSetup()
    setup.ParseFromString(base64.b64decode(io.recvline().strip().decode()))
    
    io.recvuntil(b"Request: ")
    io.sendline(base64.b64encode(c.CreateRequest(zero_encoding(0, 256)).SerializeToString()))
    resp = psi.Response()
    resp.ParseFromString(base64.b64decode(io.recvline().strip().decode()))
    intersection = c.GetIntersection(setup, resp)
    io.recvuntil(b"Computed intersection: ")
    a = intersection[0]
    # print(a)
    x = "0" * a + "1" + "0" * (256 - (a+1))
    # print(x)
    y = "0" * a + "1"
    io.sendline(y.encode())
    b = a
    history = [0]

    

    while True:
        setup = psi.ServerSetup()
        io.recvuntil(b"Size of client set: ")
        io.sendline(b"256")
        io.recvuntil(b"Setup:  ")
        setup.ParseFromString(base64.b64decode(io.recvline().strip().decode()))
        io.recvuntil(b"Request: ")


        
        io.sendline(base64.b64encode(c.CreateRequest(zero_encoding(int(x, 2), 256)).SerializeToString()))
        history.append(int(x, 2))
        resp = psi.Response()
        resp.ParseFromString(base64.b64decode(io.recvline().strip().decode()))

        b = a
        
        intersection = c.GetIntersection(setup, resp)
        if intersection == []:
            io.recvuntil(b"Computed intersection: ")
            io.sendline()
            break
        a = intersection[0]
        index = 0
        for i in range(len(x)-(a-b)-1):
            if x[i] == "1" and x[i+(a-b)+1] == "0":
                index = i+(a-b)+1
        print(index)
        x = x[:index] + "1" + "0" * (256 - (index + 1))
        y = x[:index] + "1"
        # print(y)
        # print(a-b)
        # print(x)
        io.recvuntil(b"Computed intersection: ")
        io.sendline(y.encode())
        io.recvuntil(b"Check (y/N)? ")
        io.sendline(b"N")



    
    io.recvuntil(b"Check (y/N)? ")
    io.sendline(b"y")
    io.recvuntil(b"My secret: ")
    # print(history)
    secret = int(x, 2)
    io.sendline(str(secret).encode())
    print(io.recvline())
    for i in history:
        print(io.recvuntil(b": "))
        io.sendline(str(i).encode())
        print("a")


print(io.recvline())
print(io.recvline())
print(io.recvline())
print(io.recvline())
print(io.recvline())
print(io.recvline())
print(io.recvline())
print(io.recvline())
print(io.recvline())
```
# Snap Circuits
WU:
look up garbled circuits. read up on them.

algorithm:
ask for AND and XOR tables between 0 and x wire for all flagbits.

since we know the 0 wire is 0 bit we can use this.

1. xor corresponding entries in both tables
2. locate duplicate
3. use known wire labels, hash them, xor them with the corresponding square in the AND and XOR table.
4. xor your results from the previous table. compare this with the duplicate. if the result is equal to the duplicate, then the x wire is a 1 bit. otherwise, it is a 0 bit.

proof is left as an exercise for the reader.

output.txt obtaining script:
```py
from pwn import *
import os

io = remote("challs.actf.co", 32511)
print(io.recvuntil(b"proof of work: "))
print(y:=io.recvline().strip().decode())

x = os.popen(y).read().strip()
print(x)
print(io.recvuntil(b"solution: "))
io.sendline(x.encode())

io.recvline()
writething = b""
for i in range(159):
    io.recvuntil(b"gate: ")
    io.sendline(x:= b"and 0 " + str(i+1).encode())
    print(x)
    io.recvuntil(b"gate: ")
    io.sendline(x:= b"xor 0 " + str(i+1).encode())
    print(x)

io.sendline(b"")

try:
    while True:
        writething += io.recv(timeout=0.01)
except:
    pass

f = open("outputs.txt", "wb")
f.write(writething)
```

solving script:

```py
from Crypto.Hash import SHAKE128
from Crypto.Util.strxor import strxor
from Crypto.Util.number import *

f = open('outputs.txt', "r")
outputs = f.read()
outputs = outputs.splitlines()
#print(outputs)
wires = outputs[:160]
for i in range(len(wires)):
    wires[i] = wires[i].split()[2:]
#print(wires)
tables = outputs[161:]
for i in range(len(tables)):
    tables[i] = tables[i].split()[0]
#print(tables)

xors = []

for i in range(159):
    xors.append([])
    for j in range(4):
        #print(tables[i].split()[0], tables[i+4].split()[0])
        xors[-1].append(long_to_bytes(int(tables[i*8+j], 16) ^ int(tables[i*8+j+4], 16)).hex())

for i in range(1, 160):
    key = bytes.fromhex(wires[0][0]) + bytes.fromhex(wires[i][0])
    index = bytes.fromhex(tables[i*8-8 + int(wires[0][1]) * 2 + int(wires[i][1])])
    index1 = bytes.fromhex(tables[i*8-4 + int(wires[0][1]) * 2 + int(wires[i][1])])
    shaker = SHAKE128.new(key)
    z = shaker.read(16)
    and0 = strxor(z, index)
    xor0 = strxor(z, index1)
    xor = xors[i-1]
    if xor[0] == xor[-1]:
        rept = xor[0]
        xor.pop(-1)
    else:
        rept = xor[1]
        xor.pop(1)
    if strxor(xor0, and0) == bytes.fromhex(rept):
        print(1, end = "")
    else:
        print(0, end = "")
    

#print(xors)
# key = b''.join([l.key for l in labels])
# self.shake = SHAKE128.new(key)
```

manually decode the binary to get flag: `actf{L3akY_g@rbl1ng}`
