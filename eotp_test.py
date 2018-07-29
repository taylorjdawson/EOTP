# coding=utf-8
import sys
from os import urandom
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# # # # # # # # # # # # # # # # # # #
# --------------------------------- #
# | Encrypting One Time Passwords | #
# --------------------------------- #
# # # # # # # # # # # # # # # # # # #

def H(data):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()

# Returns HMAC as 32 bytes (128 bits)
def HMAC(key, data):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

def E(key, data):
    iv = urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    cipherText = encryptor.update(data) + encryptor.finalize()

    # attach the initialization_vector to the beginning of the encrypted data
    return iv + cipherText

def D(key, data):
    # remove the initialization_vector from the beginning of the encrypted data
    iv = data[:16]
    data = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()

def xor (bytes1, bytes2):
    xor_int = int.from_bytes(bytes1, sys.byteorder) ^ int.from_bytes(bytes2,
                                                            sys.byteorder)
    return xor_int.to_bytes(len(bytes1), sys.byteorder)

RAND_NUM_SIZE = 64
bob = {}
alice = {}
alice['password'] = b'password'

# Key setup

# Alice authenticates herself to Bob using the existing password-based
# authentication.

# Compute Alice's three random number Ra, Rb, Rx
Ra = urandom(RAND_NUM_SIZE)
Rb = urandom(RAND_NUM_SIZE)
Rx = urandom(RAND_NUM_SIZE)

# Compute Bob's three random number Rc, Rd, Ry
Rc = urandom(RAND_NUM_SIZE)
Rd = urandom(RAND_NUM_SIZE)
Ry = urandom(RAND_NUM_SIZE)

# Bob and Alice both compute (and save) sequence key Ks = H(Ra || Rc).
alice['Ks'] = H(Ra + Rc)
bob['Ks'] = H(Ra + Rc)

# Bob and Alice both compute static key Kt = H(Rb || Rd).
alice['Kt'] = H(Rb + Rd)
bob['Kt'] = H(Rb + Rd)
print(f"Bob Kt: {bob['Kt']}")

# Bob and Alice both compute (and save) salt S = H(Rx || Ry).
alice['S'] = H(Rx + Ry)
bob['S'] = H(Rx + Ry)

# Bob uses a RNG to generate a master key Km.
bob['Km'] = urandom(RAND_NUM_SIZE)
print(f"Bob Km: {bob['Km']}")

# Bob computes Cm = E( HMAC(Kt, <Alice's Password>), Km) then destroys Km
key = HMAC(bob['Kt'], alice['password'])
bob['Cm'] = E(key, bob['Km'])
del bob['Km']

# Bob saves token T = HMAC(Kt || S, <Alice's Password> || S) and destroys Kt.
bob['T'] = HMAC(bob['Kt'] + bob['S'], alice['password']+ bob['S'])
del bob['Kt']

# Bob destroys all information related to Alice's password other than T.


# Bob and Alice save 128-bit counters initialized to 0. Let Ia and Ib denote Alice's and Bob's counter respectively.
alice['I'] = 0
bob['I'] = 0

print(alice)
print(bob)

#
# Authentication Procedure
#


# Alice identifies herself to Bob.

# Bob responds with the current value of his 128-bit counter.

# Alice repeatedly computes Ks = HMAC(Ks, Ia || S) and increments Ia until Ia == Ib.
while alice['I'] != bob['I']:
    alice['Ks'] = HMAC(alice['Ks'], alice['I'] + alice['S'])

# Alice computes OTP = Ks XOR Kt and sends her password and OTP to Bob.
OTP = xor(alice['Ks'], alice['Kt'])

# Bob obtains Kt = OTP XOR Ks.
bob['Kt'] = xor(OTP, bob['Ks'])

# Bob computes T' = HMAC(Kt || S, <Alice's Password> || S).
T = HMAC(bob['Kt'] + bob['S'], alice['password'] + bob['S'])

# Bob compares T' and T. If they are identical, Alice is authenticated, if not, Bob stops here.
assert bob['T'] == T

# Bob computes Km by decrypting Cm with key HMAC(Kt, <Alice's Password>).
key = HMAC(bob['Kt'], alice['password'])
bob['Km'] = D(key, bob['Cm'])

# Bob saves Ks = HMAC(Ks, Ib || S) and increments Ib.
bob['Ks'] = HMAC(bob['Ks'], bytes([bob['I']]) + bob['S'])
bob['I'] += 1

# Bob destroys of Kt and the previous Ks.
del bob['Kt']

# Bob uses Km to encrypt and decrypt Alice's data and destroys it when finished.

bob['Km']



