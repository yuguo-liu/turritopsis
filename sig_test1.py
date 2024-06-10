import time


from crypto.threshsig.boldyreva import dealer
from pypairing import G1 as G11, G2 as G22, ZR as ZRR

N=4
id = 0


sPK1, sSK1 = dealer(4, 2)

t1 = time.time()
digest1 = sPK1.hash_message(str('STORED'))
t2 = time.time()
sigma = sSK1[id].sign(digest1)
t3 = time.time()
assert sPK1.verify_share(sigma, id, digest1)
t4 = time.time()
print("all", t4-t1)
print("hash", t2-t1)
print("sign", t3-t2)
print("ver bls sigs", t4-t3)
print("=========================")


thsks = []
thpks = []

secret = 1


g2 = G22.hash(b'1')
g1 = G11.hash(b'2')

for i in range(4):
    thsks.append(ZRR.rand())
    # print(type(thsks[i]))
    thpks.append(g1 ** thsks[i])
thpk = g1 ** secret
from utils.core.bls_bn2 import sign as sign2, verify_share as vs2, hash_message as hash2

t1 = time.time()
digest1FromLeader = hash2(str("ECHO"))
t2 = time.time()
sig = sign2(thsks[id], digest1FromLeader)
t3 = time.time()
assert vs2(thpks[id], sig, digest1FromLeader)
t4 = time.time()
print("all", t4-t1)
print("hash", t2-t1)
print("sign", t3-t2)
print("ver", t4 - t3)
