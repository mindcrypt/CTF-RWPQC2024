To solve for the flag of the Xyber CTF challenge, we will have to successfully connect to the TLS server. From the prompt, we see that the server only accepts the X25519Kyber768 key exchange specified in the __X25519Kyber768Draft00 IETF draft__. This key exchange, as mentioned in the draft, is only for TLS 1.3.

What we need to know in order to solve this challenge is that, during a TLS 1.3 handshake, the following pieces of information gets exchanged:

1. First, inside the ClientHello message sent by the client, there is a key_share extension that carries some client-side key exchange data.

2. Inside the ServerHello message returned by the server, there is also a key_share extension that carries some server-side key exchange data.

3. Upon seeing both key_share extensions, both parties (client and server) are able to derive a shared secret from them, and use that shared secret to derive the actual session key.

With this knowledge in mind, we take a look at a few snippets of tlslite/keyexchange.py which contains all the key exchange code and with X25519Kyber768Draft00 handshake already implemented with placeholders.

```python
def get_random_private_key(self):
# ...
elif self.group == GroupName.x25519kyber768draft00:
    return getRandomBytes(X25519_ORDER_SIZE)
# ...

def calc_public_value(self, private):
# ...
elif self.group == GroupName.x25519kyber768draft00:
    return x25519(private, bytearray(X25519_G))
# ...

def calc_shared_key(self, private, peer_share):
# ...
elif self.group == GroupName.x25519kyber768draft00:
    S = x25519(private, peer_share)
    self._non_zero_check(s)
    return S
# ...
```

We see that there are three function calls that involve handling this particular type of key exchange. Get_random_private_key generates the key pair used for key exchange, calc_public_value outputs what key_share payload goes into the ClientHello, and lastly calc_shared_key computes the shared secret from the two key_share extensions in ClientHello and ServerHello. Right now they just implement a plain X25519 key exchange as a placeholder.

Fortunately, we only need to implement the client side here as the server side already supports the new key exchange, therefore, we just need to finish implementing the three function calls and it should just work.

Taking a closer look at __Section 3__ of the draft, we see that the construction is extremely simple.

_For the client's share, the key_exchange value contains the concatenation of the client's X25519 ephemeral share (32 bytes) and the client's Kyber768Draft00 public key (1184 bytes). The resulting key_exchange value is 1216 bytes in length._

_The shared secret is calculated as the concatenation of the X25519 shared secret (32 bytes) and the Kyber768Draft00 shared secret (32 bytes). The resulting shared secret value is 64 bytes in length._

Basically, we keep the original X25519 key exchange placeholder, and do another Kyber768 key exchange in parallel, and concatenate the data to the end of the payloads.

```python
def get_random_private_key(self):
# ...
elif self.group == GroupName.x25519kyber768draft00:
    # Random X25519 sk
    xsk = getRandomBytes(X25519_ORDER_SIZE)
    # Random Kyber768 sk
    _, ksk = Kyber768.keygen()
    # Contatenating two sk
    return xsk + ksk
# ...

def calc_public_value(self, private):
# ...
elif self.group == GroupName.x25519kyber768draft00:
    # X25519 pk
    xpk = x25519(private[:X25519_ORDER_SIZE], bytearray(X25519_G))

 # Kyber768 pk
    kpk = Kyber768.get_pk_from_sk(private[X25519_ORDER_SIZE:])
    # Concatenating to pk
    return xpk + kpk
# ...

def calc_shared_key(self, private, peer_share):
# ...
elif self.group == GroupName.x25519kyber768draft00:
    # Parse the first part of sk as X25519 private key
    xsk = private[:X25519_ORDER_SIZE]
    peer_xpk = peer_share[:X25519_ORDER_SIZE]
    # Compute X25519 shared secret
    xsecret = x25519(xsk, peer_xpk)
    self._non_zero_check(xsecret)

    # Parse the second part of sk as Kyber768 private key
    ksk = private[X25519_ORDER_SIZE:]
    peer_kencaps = peer_share[X25519_ORDER_SIZE:]
    # Compute Kyber768 shared secret (client side calls Decaps)
    ksecret = Kyber768.dec(peer_kencaps, ksk)

    # Return the concatenation of the two shared secrets
    return xsecret + ksecret
# ...
```
Upon fixing the tlslite implementation, running the client will output success and the flag.

__References__

https://www.ietf.org/archive/id/draft-tls-westerbaan-xyber768d00-03.html
