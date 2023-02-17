# Passing Notes
<br>1. bash 64 possibilities using sagemath and known plaintext
<br>2. win
<br>
here's the code:<br>
```py
from base64 import b64encode
from random import choice
from sage.all import GF

b64_alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\\="

field = list(GF(2**6))


def generate_secret_key(n):
  key = 1
  for _ in range(n):
    key *= choice(field)
    key += choice(field)
  return key


def encrypt(message, secret_key):
   message = b64encode(message)
   encrypted = ""
   mod_key = 6 * secret_key**6 + 3 * secret_key**4 + 7 * secret_key**3 + 15
   print(mod_key)
   for char in message:
      encrypted += b64_alpha[field.index(field[b64_alpha.index(chr(char))] * mod_key)]
   return encrypted
def decrypt(message):
    i = 44
    key = field[i]
    decrypted = ""
    for char in message:
        decrypted += b64_alpha[field.index(field[b64_alpha.index(char)]/key)]
    return decrypted
    
print(decrypt("V4m\\GDMHaDM3WKy6tACXaEuXumQgtJufGEyXTAtIuDm5GEHS"))
key = field[7]
print(encrypt(b'valentine{notes thing yes}', key))
print("V4m\\GDMHaDM3WKy6tACXaEuXumQgtJufGEyXTAtIuDm5GEHS")
```
This outputs some base64, which decodes to `valentine{th15_is_4_s3cret_m355age}`.
# Better Notes
bash possibilities and filter through them using python
<br>1. guess plaintext
<br>2. bash more possiblities and filter through them using python
<br>3. win
<br>
see bash code below
```py
from base64 import b64encode
import string, binascii
charset = string.ascii_lowercase + string.digits + "_@"
amble = "rtxyz"
mamble = "ev"
ambled = "qrswyz"
ample = "1"
print("WU]Wipuk\cYAvtEXHsRlP_YlPs[UMtVmkcOjupFCVGU"[22:26])
print("WU]Wipuk\cYAvtEXHsRlP_YlPs[UMtVmkcOjupFCVGU"[18:22])
print(len(charset))
for i in charset:
  for aaa in charset:
    for abcd in charset:
      for asdf in charset:
                valentine = "valentine{t3"+str(i)+str(aaa)+"_"+str(abcd) + str(asdf)+"_w1nky_f4ce}"
                valentine = valentine.encode()
                a = b64encode(valentine)
                b = b64encode(valentine[::-1])
                a = list(map(ord, list(str(a))))
                b = list(map(ord, list(str(b))))
                valentines = ""
                for j in range(len(a)):
                  valentines += chr((a[j] + b[j]) % 58 + 65)
                if valentines[22:26] == "YlPs":
                  if valentines[18:22] == "RlP_":
                    print(i, aaa, abcd, asdf)
```
flag is `valentine{t3xt_me_w1nky_f4ce}`.
