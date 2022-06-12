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

Source:
```python
from Crypto.Util.number import *
import random
import itertools
flag = open('flag.txt','rb').read()
pt = bytes_to_long(flag)
p,q = getPrime(512),getPrime(512)
n = p*q
a = random.randint(0,2**512)
b = random.randint(0,a)
c = random.randint(0,b)
d = random.randint(0,c)
e = random.randint(0,d)
f = 0x10001
g = [[-a,0,a],[-b,0,b],[-c,0,c],[-d,0,d],[-e,0,e]]
h = list(pow(sum(_),p,n) for _ in itertools.product(*g))
random.shuffle(h)
print(h[0:len(h)//2])
print(n)
print(pow(pt,f,n))
```
Clearly we need to do something with the list of numbers we're given, as the primes are too big to factor. Notice how the numbers are in the form of x^p (mod n), and from Fermat's Little Theorem, we have that this is equivalent to x (mod p). Since it is mod p*q, it is likely that the numbers are greater than p, given that p is a 512 bit prime and all of the numbers we're given are higher than that. Let's look at how it generates x: It adds 1 number from each list of `[-a,0,a],[-b,0,b],[-c,0,c],[-d,0,d],[-e,0,e]`, and it doesn't really matter what a, b, c, d, e are. Given this, we want to get `p` by adding a few of the values we're given, and then taking the gcd of that with `n` (because one of its factors are p), and seeing whether that's greater than 0 or not, and hoping that the gcd isn't just `n`. Let's write some code to add 2 of the given values.

*insert code here*

Well this didn't work because all the outputs are just n. Clearly we need to scale up the amount of numbers we're adding. Trying this with 3 numbers, we find that `p = 8232743274837446463598254637051161045911091397541451296000991485083369905136689783513169363218917147263240294508530778763390359497242952090254975434412391`. Plugging our numbers into dcode.fr's RSA decoder, we find that the flag is `flag{sometimes_you_just_want_to_make_long_flags_because_you_want_to_and_also_because_you_dont_know_what_else_you_can_put_here}`
