import random
import numpy as np
import gevent
from gevent import Greenlet
from gevent.queue import Queue

from crypto.ecdsa.ecdsa import pki
from dumbobft.core.consistentbroadcast import consistentbroadcast
# from crypto.threshsig import dealer
import hashlib, pickle
from crypto.ecdsa.ecdsa import ecdsa_vrfy, ecdsa_sign

def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()
f=3
l=2
n=3*f+2*l+1
# CBC
m='123'
PK2s, SK2s = pki(n+l)
c_old = [i for i in range(n)]
c_new = [i+l for i in range(n)]
print("old:", [i for i in range(n)])
print("new:", [i+l for i in range(n)])
digestFromLeader = hash(m)
# print("leader", pid, "has digest:", digestFromLeader)
sig = ecdsa_sign(SK2s[1], digestFromLeader)
last = sig[-1]
reversed_last = last ^ 0x01
sig0 = sig[:-1] + bytes([reversed_last])
print(sig)
print(sig0)
print(ecdsa_vrfy(PK2s[1], digestFromLeader, sig))
print(ecdsa_vrfy(PK2s[1], digestFromLeader, sig0))
seed =1
a = hash(seed)
np.random.seed(int.from_bytes(a, byteorder='big') % 1000)
pi = np.random.permutation([i for i in c_old])
l_node = [i for i in range(l)]
print("malicious in old", pi[:f])
count = 0
for i in pi[:f]:
    if i in l_node:
        count += 1
pi2 = np.random.permutation([i for i in list(set(c_new) - set(c_old))])
print("malicious in old", pi2[:(count)])
