from pwn import *
from string import *
from base64 import *
import time
import json

r=remote('127.0.0.1',11337)
r.recv()

def getCipher():
  r.send('1\n')
  r.recv()

  r.send('1234\n')
  time.sleep(0.1)
  res = r.recv().split('\n')[0].split(':')[1].strip()
  return res

def xor(s1,s2):
  return ''.join([chr(ord(a)^ord(b)) for a,b in zip(s1,s2)])

def getBlock():
  b64 = getcipher()
  time.sleep(0.3)
  s = b64decode(b64)
  s= s[(len(s)/64)*64:]
  b = (len(s)+1)/4-1
  if b == -1:
    b += 16
  return b, b64decode(b64)[-4:]

def check(keyarr, cipher):
  lst=[]
  for kn in keyarr:
    try:
      dc = b64decode(xor(kn , cipher))
      if len(dc) == 1 and dc=='}':
        lst.append(kn)
      elif len(dc) == 2 and dc=='"}':
        lst.append(kn)
      elif '"}' in dc and dc[0] in (letters + digits):
        lst.append(kn)
    except:
      pass
  return lst
xor_key = ''
for i in range(0,16):
  c2=''
  c1=''
  while True:
    block, c1 = getBlock()
    if block == i:
      break
  while True:
    a, c2 = getBlock()
    if a == block and c1 != c2:
      break
  keyarr=[]
  keyarr.append(xor(c1 , b64encode('}')))
  keyarr.append(xor(c1 , b64encode('"}')))
  for i in (letters+digits):
    keyarr.append(xor(c1 , b64encode(i+'"}')))
  lst = check(keyarr, c2)
  while len(lst) > 1:
    while True:
      a, c2 = getBlock()
      if a == block and c1 != c2:
        break
    lst = check(lst, c2)
  xor_key += lst[0]
  print xor_key

finish = b64decode(getcipher())
a,b = divmod(len(finish),len(xor_key))
decrypt = b64decode(xor(finish,xor_key*a + xor_key[:b]))
print
print decrypt
print
print json.loads(decrypt)['flag']
