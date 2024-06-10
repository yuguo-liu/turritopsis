import time

import ipcl_python
import numpy as np
from ipcl_python import PaillierKeypair

import phe

def bytes2Int(val) -> int:
    return int.from_bytes(val, "little")

def BN2int(val) -> int:
    """
    Convert BigNumber to Python integer

    Args:
        val: BigNumber

    Returns:
        Python integer representation of BigNumber
    """
    return bytes2Int(val.to_bytes())
pk1, sk1 = phe.paillier.generate_paillier_keypair(n_length=2048)

pk, sk = PaillierKeypair.generate_keypair(2048, True)
a = 100
s1 = time.time()
# print(pk.apply_obfuscator(1))
ct_a = pk.encrypt(a)
s2 = time.time()
de_a = sk.decrypt(ct_a)
s3 = time.time()
print(de_a)
print("intel enc:", s2-s1)
print("intel dec:", s3-s2)

b = 2
c_b = pk.encrypt(b)

print((BN2int(c_b.ciphertextBN()[0]) * BN2int(ct_a.ciphertextBN()[0])) % pk.nsquare)
print(pk.nsquare)
print(pk.apply_obfuscator(100))
print(pk.apply_obfuscator(200))
print(pk.apply_obfuscator(200))

"""
s1 = time.time()
ct_a = pk1.encrypt(a, 5)
s2 = time.time()
de_a = sk1.decrypt(ct_a)
s3 = time.time()
print("phe enc:", s2-s1)
print("phe dec:", s3-s2)"""


