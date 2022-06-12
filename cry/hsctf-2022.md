# OTP
We're given an output, consisting of the bit-length of a randomly generated number, and the flag xored with that number. We're also given the program used to generate the number:
```python
import random
from Crypto.Util.number import bytes_to_long

def secure_seed():
	x = 0
	# x is a random integer between 0 and 100000000000
	for i in range(10000000000):
		x += random.randint(0, random.randint(0, 10))
	return x

flag = open('flag.txt','rb').read()
flag = bytes_to_long(flag)

random.seed(secure_seed())

l = len(bin(flag)) - 1
print(l)

k = random.getrandbits(l)
flag = flag ^ k # super secure encryption
print(flag)
```
The function `secure_seed()` is defined weirdly. It adds 10 billion values of x together, where x is a random integer between 0 and a random integer between 0 and 10. Since you're doing this 10 billion times, there must be some sort of statistical analysis you can do here. Testing this with smaller amounts of x added together, we see that it tends towards 2.5*n, where n is the amount of x you're adding together. Using the smaller amounts of x we calculated earlier, and graphing the deviations on desmos, we can calculate the deviation of n=10,000,000,000 to be around 250k. Therefore, we can write the following code to brute force the seed that encrypts the flag.
```python
import random
n = 250000
x = 25000000000 - n
fleg = 444466166004822947723119817789495250410386698442581656332222628158680136313528100177866881816893557
for i in range(2*n):
    x += 1
    random.seed(x)
    k = random.getrandbits(328)
    flag = fleg^k
    binary_array = flag.to_bytes(41, "big")
    try:
        ascii_text = binary_array.decode()
        print(ascii_text)
        break
    except (UnicodeDecodeError):
        a = 0
```
Which outputs the flag: `flag{c3ntr4l_l1m1t_th30r3m_15431008597}`




# Baby RSA
Again, we're given an output, and the program that prints the outputs. This time, it appears that we're given the public key, the ciphertext (encrypted with RSA), and half of a randomized list of numbers in the form of x^p (mod n).
