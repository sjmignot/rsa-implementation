# -*- coding: utf-8 -*-
"""
simple RSA implementation for python. Made for learning purposes...

- samuel mignot
"""

import binascii
from Crypto.Util import number
import numpy as np
from functools import wraps
from time import time

from collections import namedtuple

PublicKey = namedtuple('PublicKey', ['n', 'e'])
PrivateKey = namedtuple('PrivateKey', ['n', 'd'])

# consts
ENCRYPTION_LENGTH = 10
e = 7

def timed(f):
    '''timing helper'''
    @wraps(f)
    def wrapper(*args, **kwargs):
        start = time()
        result = f(*args, **kwargs)
        end = time()
        print(f"Elapsed time: {end-start}")
        return result
    return wrapper

def encode_string(s):
    '''takes a string and returns its int representation'''
    return int.from_bytes(s.encode('utf-8'), byteorder='big')

def decode_int(i):
    '''takes an int and returns its utf-8 string representation'''
    #return binascii.unhexlify(format(i, 'x').encode('utf-8')).decode('utf-8')
    return ((i).to_bytes((i.bit_length()+7)//8, byteorder='big')).decode("utf-8")

def generate_large_primes():
    '''generates a tuple of large primes (size is definited by encryption length'''
    return tuple(number.getPrime(ENCRYPTION_LENGTH) for i in range(2))

def naive_totient(n):
    '''calculate totient very naively'''
    return sum([int(np.gcd(x, n)==1) for x in range(1, n+1)])

def totient_2p(p,q):
    '''calculate totient for multiple of two primes'''
    return (p-1)*(q-1)

def encrypt(message, public_key):
    '''encrypt a message using public key'''
    int_message = encode_string(message)
    print(f"int message: {int_message}")
    n, e = public_key.n, public_key.e
    encrypted_message = pow(int_message, e, n)
    return encrypted_message

def decrypt(int_message, private_key):
    '''decrypts a message using private and public key'''
    n, d = private_key.n, private_key.d
    decrypted_message = pow(int_message, d, n)
    return decode_int(decrypted_message)


# @timed # test the speed of numpy vs egcd implementaitons
def egcd(a, m):
    if np.gcd(a, m) != 1:
        main() #rerun on fail

    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m

    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m

# @timed # test the speed of numpy vs egcd implementaitons
def npegcd(a, m):
    if np.gcd(a, m) != 1:
        main() #rerun on fail

    arr = np.array([1, 0, a, 0, 1, m]).reshape(2,-1)

    while arr[1,2] != 0:
        q = arr[0,2] // arr[1,2]
        arr = np.vstack((arr[1], arr[0,:]-(q*arr[1,:])))
    return arr[0,0]%m

def generate_private_key(e, phi):
    '''uses phi, e, and n to generate the private key'''
    return egcd(e, phi)

def main():
    '''main function calculates large primes, public key and private key'''
    p, q = generate_large_primes()
    n =  p*q
    phi = totient_2p(p, q)
    d = generate_private_key(e,phi)
    public_key = PublicKey(n=n, e=e)
    private_key = PrivateKey(n=n, d=d)
    print(f"large primes: p={p}, q={q}")
    print(f"phi: {phi}")
    print(f"generated the following keys with e={e} and RSA-{ENCRYPTION_LENGTH}: ")
    print(f"public_key: {public_key}")
    print(f"private_key: {private_key}")
    print()
    message = input('what message do you want to encrypt? ').strip()
    x = encode_string(message)
    print(x)
    print(decode_int(x))
    encrypted_message = encrypt(message, public_key)
    print()
    decrypted_message = decrypt(encrypted_message, private_key)
    print(f"decrypted message: {decrypt(encrypted_message, private_key)}")

if __name__ == '__main__':
    main()
