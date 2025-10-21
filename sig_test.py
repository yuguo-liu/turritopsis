import time
from coincurve import PrivateKey, PublicKey
from utils.core.bls_bn import sign, verify_share, verify_signature, hash_message, combine_shares
from utils.core.serializer import serialize_G2,deseralize_G2
import os
import hashlib, pickle
from crypto.ecdsa.ecdsa import ecdsa_vrfy, ecdsa_sign
from utils.core.serializer import serialize, deserialize
from crypto.threshsig.boldyreva import dealer
from pypairing import G1 as G11, G2 as G22, ZR as ZRR, blsmultiexp, pair as pairr
import logging
from crypto.threshsig.boldyreva import serialize, deserialize1
from crypto.threshsig.boldyreva import TBLSPrivateKey, TBLSPublicKey
N=4
id = 0
with open(os.getcwd() + '/keys-' + str(N) + '/' + 'thSK1-' + str(id) + '.key', 'rb') as fp:
    thsk = pickle.load(fp)

with open(os.getcwd() + '/keys-' + str(N) + '/' + 'thPK1' + '.key', 'rb') as fp:
    thpk = deserialize(pickle.load(fp))

thpks = []
for i in range(N):
    with open(os.getcwd() + '/keys-' + str(N) + '/' + 'thPK1-' + str(i) + '.key', 'rb') as fp:
        thpks.append(deserialize(pickle.load(fp)))

sPK2s = []
for i in range(N):
    with open(os.getcwd() + '/keys-' + str(N) + '/' + 'sPK2-' + str(i) + '.key', 'rb') as fp:
        sPK2s.append(PublicKey(pickle.load(fp)))
with open(os.getcwd() + '/keys-' + str(N) + '/' + 'sSK2-' + str(id) + '.key', 'rb') as fp:
    sSK2 = PrivateKey(pickle.load(fp))

with open(os.getcwd() + '/keys-' + str(N) + '/' + 'eSK1-' + str(id) + '.key', 'rb') as fp:
    eSK = pickle.load(fp)

print("\033[35m[TEST]\033[0m Case 1: BLS Signature Test Case")
sPK1, sSK1 = dealer(4, 2)
t1 = time.time()
digest1FromLeader = hash_message(str("ECHO"))
t2 = time.time()
sig = sign(thsk, digest1FromLeader)
t3 = time.time()
s_sig = serialize_G2(sig)
t4 = time.time()
d_sig = deseralize_G2(s_sig)
t5 = time.time()
assert verify_share(thpks[id], d_sig, digest1FromLeader)
t6 = time.time()
print("\033[32m[PASS]\033[0m Case 1 passed")
print("|---\033[33m[TIME]\033[0m all:  ", t6-t1, "s")
print("|---\033[33m[TIME]\033[0m hash: ", t2-t1, "s")
print("|---\033[33m[TIME]\033[0m sign: ", t3-t2, "s")
print("|---\033[33m[TIME]\033[0m se:   ", t4-t3, "s")
print("|---\033[33m[TIME]\033[0m de:   ", t5-t4, "s")
print("|---\033[33m[TIME]\033[0m ver:  ", t6-t5, "s")

print("\033[35m[TEST]\033[0m Case 2: ECDSA Test Case")
def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()
t1 = time.time()
digest1FromLeader = hash(str("ECHO"))
t2 = time.time()
sig = ecdsa_sign(sSK2, digest1FromLeader)
t3 = time.time()
for i in range(16):
    assert ecdsa_vrfy(sPK2s[id], digest1FromLeader, sig)
t4 = time.time()
print("\033[32m[PASS]\033[0m Case 2 passed")
print("|---\033[33m[TIME]\033[0m all:        ", t4-t1, "s")
print("|---\033[33m[TIME]\033[0m hash:       ", t2-t1, "s")
print("|---\033[33m[TIME]\033[0m sign:       ", t3-t2, "s")
print("|---\033[33m[TIME]\033[0m ver16 sigs: ", t4-t3, "s")

print("\033[35m[TEST]\033[0m Case 3: Threshold BLS Signature Test Case")
t1 = time.time()
digest1 = sPK1.hash_message(str('STORED'))
t2 = time.time()
sigma = sSK1[id].sign(digest1)
t3 = time.time()
assert sPK1.verify_share(sigma, id, digest1)
t4 = time.time()
print("\033[32m[PASS]\033[0m Case 3 passed")
print("|---\033[33m[TIME]\033[0m all:          ", t4-t1, "s")
print("|---\033[33m[TIME]\033[0m hash:         ", t2-t1, "s")
print("|---\033[33m[TIME]\033[0m sign:         ", t3-t2, "s")
print("|---\033[33m[TIME]\033[0m ver bls sigs: ", t4-t3, "s")

print("\033[35m[TEST]\033[0m Case 4: Pairing-Based Threshold BLS Signature Test Case")
from adkr.acss.core.polynomial_pairing import polynomials_over_BN as polynomials_over_BN_N

thsks = []
thpks = []
poly = polynomials_over_BN_N(ZRR)
secret = 1
phi = poly.random(1, secret)

g2 = G22.hash(b'1')
g1 = G11.hash(b'2')

for i in range(4):
    thsks.append(phi(i + 1))
    # print(type(thsks[i]))
    thpks.append(g1 ** phi(i + 1))
thpk = g1 ** secret
from utils.core.bls_bn2 import sign as sign2, verify_share as vs2, hash_message as hash2

t1 = time.time()
digest1FromLeader = hash2(str("ECHO"))
t2 = time.time()
sig = sign2(thsks[id], digest1FromLeader)
t3 = time.time()
assert vs2(thpks[id], sig, digest1FromLeader)
t4 = time.time()
print("\033[32m[PASS]\033[0m Case 4 passed")
print("|---\033[33m[TIME]\033[0m all:  ", t4-t1, "s")
print("|---\033[33m[TIME]\033[0m hash: ", t2-t1, "s")
print("|---\033[33m[TIME]\033[0m sign: ", t3-t2, "s")
print("|---\033[33m[TIME]\033[0m ver:  ", t4-t3, "s")
