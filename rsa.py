# -*- coding: utf-8 -*-
"""
simple RSA implementation for python. Made for learning purposes...

- samuel mignot
"""

from Crypto.Util import number
import numpy as np
from functools import wraps
from time import time

from collections import namedtuple

# consts
encryption_length = 2048
e = 7

# key objects
PublicKey = namedtuple('PublicKey', ['n', 'e'])
PrivateKey = namedtuple('PrivateKey', ['n', 'd'])

def encode_string(s):
    '''takes a string and returns its int representation'''
    return int.from_bytes(s.encode('utf-8'), byteorder='big')

def decode_int(i):
    '''takes an int and returns its utf-8 string representation'''
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

def encrypt(int_message, public_key):
    '''encrypt a message using public key'''
    n, e = public_key.n, public_key.e
    encrypted_message = pow(int_message, e, n)
    return encrypted_message

def decrypt(int_message, private_key):
    '''decrypts a message using private and public key'''
    n, d = private_key.n, private_key.d
    decrypted_message = pow(int_message, d, n)
    return decode_int(decrypted_message)


def egcd(a, m):
    '''calculate extended euclid algorithhm'''
    if np.gcd(a, m) != 1:
        print('randomly selected primes not compatible. Please run again')
        exit()

    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m

    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m

def npegcd(a, m):
    '''calculate extended euclid algorithhm with numpy arrays'''
    if np.gcd(a, m) != 1:
        print('randomly selected primes not compatible. Please run again')
        exit()

    arr = np.array([1, 0, a, 0, 1, m]).reshape(2,-1)

    while arr[1,2] != 0:
        q = arr[0,2] // arr[1,2]
        arr = np.vstack((arr[1], arr[0,:]-(q*arr[1,:])))
    return arr[0,0]%m

def generate_private_key(e, phi):
    '''uses phi, e, and n to generate the private key'''
    return egcd(e, phi)

def print_variable_details(p, q, phi, e, encryption_length, public_key, private_key):
    '''prints some basic details about the intermediary encrpytion variables and keys'''
    print(f"large primes: p={p}, q={q}")
    print(f"phi: {phi}")
    print(f"generated the following keys with e={e} and RSA-{encrpytion_length}: ")
    print(f"public_key: {public_key}")
    print(f"private_key: {private_key}")
    print()

def get_user_message(n):
    '''
    Gets a message as input from the user and verifies that the message is shorter than n (which is an encryption requirement).
    For messages larger than n, normal encryption methods use RSA to generate a symetric key.
    '''
    int_message = pow(10, len(str(n))+1)
    while len(str(int_message)) > len(str(n)):
        message = input('what message do you want to encrypt? ').strip()
        int_message = encode_string(message)
        if len(str(int_message)) > len(str(n)):
            print(f"please enter a shorter message.", end="")
            print(f"Your message currently encodes to a length of {len(str(int_message))}, but it must shorter than {len(str(n))}")
    print(f"int message: {int_message}")
    return int_message


def main():
    '''main function calculates large primes, public key and private key'''
    p, q = generate_large_primes()
    n =  p*q
    phi = totient_2p(p, q)
    d = generate_private_key(e,phi)
    public_key = PublicKey(n=n, e=e)
    private_key = PrivateKey(n=n, d=d)

    print_details(p, q, phi, e, encryption_length, public_key, private_key)

    int_message = get_user_message(n)

    encrypted_message = encrypt(int_message, public_key)
    print(f"encrypted message: {encrypted_message}")

    decrypted_message = decrypt(encrypted_message, private_key)
    print(f"decrypted message: {decrypt(encrypted_message, private_key)}")

if __name__ == '__main__':
    main()
