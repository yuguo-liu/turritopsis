import time

from adkr.keyrefersh.core.poly_misc_bn import lagrange_c1
from functools import reduce
from operator import mul
from utils.core.betterpairing import G1, G2, ZR, pair
import pickle
from g_thresh_gen import generate_thre_new
from collections import defaultdict
g2 = G2.hash(b'1')
g1 = G1.hash(b'2')
print(g1, g2)
def hash_message(m):
    """ """
    try:
        m = pickle.dumps(m)
    except:
        pass
    return G2.hash(m)

def sign(sk, h):
    """ """
    return h ** sk

def verify_share(pk, sig, h):
    """ """

    assert pair(g1, sig) == pair(pk, h)

    return True

def combine_shares(sigs):
    """ """
    # sigs: a mapping from idx -> sig
    S = set(sigs.keys())
    # assert S.issubset(range(self.l))
    res = G2.identity()
    for j, sig in sigs.items():
        a = lagrange_c1(S, j)
        res *= sig ** a

    return res

def verify_signature(pk, sig, h):
    """ """
    assert pair(g1, sig) == pair(pk, h)
    return True


"""g10, g20, thpk, thpks, thsks = generate_thre_new(4, 2)
msg = '123321'
hash = hash_message(msg)
sigs = defaultdict()
s0 = time.time()
for i in range(4):
    s1 = time.time()
    sigs[i] = sign(thsks[i], hash)
    s2 = time.time()
    print("sign:", s2 - s1)
    print(verify_share(thpks[i], sigs[i], hash))
    s3 = time.time()
    print("verify:", s3 - s2)
s4 = time.time()
ss = dict(list(sigs.items())[:3])
sig = combine_shares(ss)
s5 = time.time()
print("combine:", s5-s4)
print(verify_signature(thpk, sig, hash))
s6 = time.time()
print("verify all:", s6 - s5)
print("all", s6 - s0)
"""
