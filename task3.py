#!/usr/bin/env python3

import socket
import subprocess
import base64
import json
import random
import gmpy2
gmpy2.get_context().precision = 4096

from binascii import unhexlify
from functools import reduce
from gmpy2 import root
import threading

def bytes_to_n(b):
    n = 0
    p = 1
    for byte in b:
        n += byte * p
        p *= 256
    return n


def n_to_bytes(n):
    b = []
    while n:
        b.append(n % 256)
        n //= 256
    return bytes(b)


class RSA:
    def __init__(self, key_bits=1024):
        self.n = None
        self.e = 257
        self.d = None

        self.key_bits = key_bits

    def generate_pq(self):
        self.q = gmpy2.next_prime(random.getrandbits(self.key_bits // 2))
        self.p = gmpy2.next_prime(random.getrandbits(self.key_bits // 2))

    def generate_key(self):
        self.generate_pq()
        self.n = self.p * self.q

        phi = (self.p - 1) * (self.q - 1)
        self.d = gmpy2.invert(self.e, phi)

    def encrypt_n(self, m: int):
        return gmpy2.powmod(m, self.e, self.n)

    def decrypt_n(self, c: int):
        return gmpy2.powmod(c, self.d, self.n)

    def encrypt(self, m: bytes):
        return n_to_bytes(self.encrypt_n(bytes_to_n(m)))

    def decrypt(self, c: bytes):
        return n_to_bytes(self.decrypt_n(bytes_to_n(c)))

    def get_public_key(self):
        return {
            'n': int(self.n),
            'e': int(self.e)
        }


def netcat(hostname, port, content):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, port))
    s.sendall(content)
    s.shutdown(socket.SHUT_WR)
    while 1:
        data = s.recv(1024)
        if data == b"":
            break
        return repr(data)
    s.close()

keys = []
n_items = 257 

def list_append():
    while len(keys) < n_items:
        try:
            raw = netcat('ionagamed.ru', 20021, b'')
            raw = raw.split()
            with lock:
                if len(keys) < n_items:
                    keys.append((bytes_to_n(base64.b64decode(raw[8][2:-3])), int(raw[4][:-1])))
                    print(len(keys))
        except AttributeError:
            # print('error')
            pass

def chinese_remainder_theorem(items):
    # Determine N, the product of all n_i
    N = 1
    for a, n in items:
        N *= n

    # Find the solution (mod N)
    result = 0
    for a, n in items:
        m = N // n
        r, s, d = extended_gcd(n, m)
        if d != 1:
            raise("Input not pairwise co-prime")
        result += a * s * m

    # Make sure we return the canonical solution.
    return result % N


def extended_gcd(a, b):
    x, y = 0, 1
    lastx, lasty = 1, 0

    while b:
        a, (q, b) = b, divmod(a, b)
        x, lastx = lastx - q * x, x
        y, lasty = lasty - q * y, y

    return (lastx, lasty, a)


def main():
    global lock
    lock = threading.Lock()
    jobs = []
    procs = 5
    for i in range(procs):
        process = threading.Thread(target=list_append)
        jobs.append(process)

    for j in jobs:
        j.start()
    
    for j in jobs:
        j.join()

    C = chinese_remainder_theorem(keys)
    M = int(root(C, n_items))
    print(n_to_bytes(M))

    # print(keys)


        
main()
