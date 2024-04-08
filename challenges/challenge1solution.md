```python
import numpy as np
from sympy import symbols, rem, expand #library

fixed=True
#K = 2
N = 16
q = 251

# reduction mod q
def modNQ(a):
    return np.asarray([a[i]%q for i in range(N)])

# product mod X^N+1
def productModN(a, b):
    tmp = np.zeros(N, int)
    for i in range(N):
      for j in range(i):
        tmp[j] -= a[i] * b[N+j-i]
      for j in range(i,N):
        tmp[j] += a[i] * b[j-i];
    return tmp

# the polynomials are entered by increasing power order
t1 = [9,145,210,114,215,36,243,174,134,22,205,240,177,107,188,109]
t2 = [235,240,154,224,34,247,155,30,124,96,224,217,184,120,159,198]

A1 = [180,198,3,194,39,34,122,189,209,91,209,5,88,25,229,195]
A2 = [229,246,105,8,222,24,73,11,212,71,138,77,30,58,83,187]
A3 = [234,73,111,41,243,53,177,232,246,63,155,43,177,224,95,84]
A4 = [64,170,216,188,196,78,33,181,222,247,116,177,51,143,85,3]
```

What follows is an example collision-based cryptanalysis code that retrieves $s_1$, $s_2$. Let:

![formula](challenges/images/image1.png)

We are searching for two binary polynomials $s_1$, $s_2$ of degree 16 s.t. $f(s_1) - g(s_2)$ has coordinates $\in \{-1,0,+1\} \mod q$

This means the unique $s_1$, $s_2$ such that: $$\textrm{check}(f(s_1),g(s_2))\textrm{ is True}.$$

```python
def f(s):
  return np.concatenate((modNQ(t1 - productModN(A1,s)), modNQ(t2 - productModN(A3,s))), axis=None)

def g(s):
  return np.concatenate((modNQ(productModN(A2,s)), modNQ(productModN(A4,s))), axis=None)

# checks if two 16-dim vectors mod q differ by 1,0,-1
def check(u,v):
  for i in range(2*N):
    if abs((u[i]-v[i]+125)%q-125)>1:
      return False
  return True
```


We could enumerate the $2^{32}$ pairs $𝑠_1$, $𝑠_2$ directly, but it would take some time (roughly a few hours) to do so.

It is more satisfactory to use a collision-search time/memory trade-off algorithm to obtain the solution within a few minutes only:

We enumerate the $2^{16}$ possible 𝑓($𝑠_1$), and index them by their first 3 coordinates mod 𝑞 (there are at most $𝑞^3$≈16 millions buckets.)

```python
# if u is a binary polynomial of degree N, change it to the next one in lexicographical order.
# this allows to iterate over the 2^16 binary polynomials.
def next_array(u):
  for i in range(N):
    if (u[i]==0):
      u[i]=1
      return True
    u[i]=0
  return False

# given 3 coordinates mod q, return the corresponding integer bucket index
# since it is easier to use integer indexes in dictionaries.
def keyof(u0,u1,u2):
  return (u0%q) + q*(u1%q) + q*q*(u2%q)

# for all coordinates u,v,w mod q,
#   pool[keyof(u,v,w)] contains all the tuples (f(s),s)
#                      where s is binary and f(s) start with u,v,w
pool={}
for i in range(q*q*q):
  pool[i]=[]

# this is the loop to populate pool.
att_s1=np.zeros(N, int)
for i in range(65536):
  v = f(att_s1)
  pool[keyof(v[0],v[1],v[2])].append(np.concatenate((v, att_s1), axis=None))
  next_array(att_s1)
```

Finally, we remark that for each $𝑠_2$, there are only 8 buckets that can contain a value 𝑓($𝑠_1$) that is close to 𝑔($𝑠_2$): we just enumerate these 8 buckets and check if we have a match.

```Python
def recover_keys():
  att_s2=np.zeros(N, int)
  for i in range(65536):
    v = g(att_s2)
    for x0 in range(-1,2):
      for x1 in range(-1,2):
        for x2 in range(-1,2):
          for w in pool[keyof(v[0]+x0,v[1]+x1,v[2]+x2)]:
            if check(v,w):
              return (w[2*N:],att_s2)
    next_array(att_s2)
  return None

(s1,s2) = recover_keys()
print('Found s2=%s' % s2)
print('Found s1=%s' % s1)
```
Found s2=[1 0 0 0 1 0 1 1 1 0 0 1 0 1 1 1]

Found s1=[1 1 1 1 1 0 1 1 0 0 0 1 0 0 1 1]

Now that we have recovered the private key, we can safely use it to decrypt the challenge!

```python
# this is the encrypted session key
u1 = [49,227,248,198,5,218,34,86,30,121,37,124,19,243,118,49]
u2= [112,190,242,199,70,141,85,141,128,82,224,218,28,147,70,41]
v= [29,156,77,121,232,189,96,34,16,86,80,165,81,72,206,78]
# this is the phase just before rounding
predec = modNQ(v - productModN(u1,s1) - productModN(u2,s2))
print('Decrypt before rounding: %s' % predec)
```
Decrypt before rounding: [123   0 248 120 249 122 125   1   0 120 128 125   1 245   0 128]

```python
# rounding function: anything closer to q/2 than to 0 mod q gets decoded as 1,
# the rest becomes is decoded as 0
def decode(x):
  if ((x+(q//4))%q) > (q//2):
    return 1
  else:
    return 0

# decode and present the flag by decreasing powers.
decrypted = [str(decode(predec[N-1-i])) for i in range(N)]
print('Decrypted session key (by decreasing powers): flag=%s' % ''.join(decrypted))
```
Decrypted session key (by decreasing powers): flag=1000111001101001
