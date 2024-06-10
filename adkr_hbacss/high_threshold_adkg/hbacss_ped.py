# coding=utf-8
import time
from collections import defaultdict
import logging
import os

import ecdsa
import gevent
import zfec
import hashlib
import math
from adkr.acss.core.reliablebroadcast import encode, decode, ceil, merkleTree, merkleVerify, getMerkleBranch

from utils.core.betterpairing import G2, G1, ZR
from pypairing import blsmultiexp
g2 = G2.hash(b'1')
g1 = G1.hash(b'2')
h = G1.hash(b'3')
from pickle import dumps, loads

from adkr.acss.core.polynomial_pairing import polynomials_over_BN as polynomials_over_BN_N
from adkr_hbacss.high_threshold_adkg.AES import AESCipher
import random
import traceback
from utils.core.serializer import serialize, deserialize
from adkr.keyrefersh.core.poly_misc_bn import interpolate_at_x1, interpolate_g1_at_x

n = 7
f = 2
SKs = []
PKs = []
kds = []
dealer = 0
ciphers = []

for i in range(n):
    SKs.append(ZR.rand())
    PKs.append(g1 ** SKs[i])
skd = SKs[dealer]
pkd = PKs[dealer]
for i in range(n):
    kds.append(PKs[i] ** skd)
    ciphers.append(AESCipher(str(kds[i])))


m = 111

poly = polynomials_over_BN_N(ZR)
deg = f
def gen_dual_code(n, degree, poly):
    def get_vi(i, n):
        out = ZR(1)
        for j in range(1, n + 1):
            if j != i:
                out = out / (i - j)
        return out

    q = poly.random(n - degree - 2)
    q_evals = [q(i + 1) for i in range(n)]
    return [q_evals[i] * get_vi(i + 1, n) for i in range(n)]

dual_codes = {}
s = time.time()
dual_codes[(deg,n)] = gen_dual_code(n, deg, poly)

def check_degree(claimed_degree, commitments):

    if (claimed_degree, len(commitments)) not in dual_codes.keys():
        dual_codes[(claimed_degree, len(commitments))] = \
            gen_dual_code(len(commitments), claimed_degree, poly)
    print(len(commitments), claimed_degree)
    dual_code = dual_codes[(claimed_degree, len(commitments))]
    check = G1.identity()
    for i in range(len(commitments)):

        check *= commitments[i] ** dual_code[i]
    print("???", check)
    return check == g1 ** 0

def Ped_Verify(g, h, commit, i, si, ri, f):
    res = G1.identity()
    for j in range(f+1):
        res *= commit[j] ** ((i+1) ** j)
    print(res)
    print((g ** si) * (h ** ri))
    return res == (g ** si) * (h ** ri)

def deal(f, m):
    # poly = polynomials_over_BN_N(ZR)
    r = ZR.rand()
    phi = poly.random(f, m)
    phi2 = poly.random(f, r)
    # print(phi(2))
    script = []
    script2 = []
    commit = []
    N = 3* f +1
    # commit0 = (g ** phi.coeffs[0])*(g2 ** phi.coeffs[0])
    for i in range(f+1):
        print(phi.coeffs[i])
        commit.append((g1 ** phi.coeffs[i]) * (h ** phi2.coeffs[i]))
    for i in range(n):
        print(phi(i+1))
        c1 = ciphers[i].encrypt(str(phi(i+1)))
        c2 = ciphers[i].encrypt(str(phi2(i + 1)))
        script.append(c1)
        script2.append(c2)
    return script, script2, commit

s = time.time()

script, script2, commit = deal(f, 11)
e = time.time()
print(e-s)

gs=[]
def Verify_and_decrypt(g, h, pid, commit, script_i, script2_i, t):
    gs = []

    si = ciphers[pid].decrypt(script_i)
    ri = ciphers[pid].decrypt(script2_i)
    # ri = ciphers[pid].decrypt(c2)
    # share = group.init(ZR, int(si))
    # random = group.init(ZR, int(ri))
    share = ZR(si)
    share_r = ZR(ri)
    # random = ZR(ri)
    # print("it is", share)
    # Verify_proof(g1, PKs[pid], pkd, c, z, kds[pid])
    s1 = time.time()
    # assert check_degree(t, commit)
    # assert g1 ** share == commit[pid]
    if Ped_Verify(g, h, commit, pid, share, share_r, t):
        print("===", time.time()-s1)
        return share, share_r
    else:
        return False
shares=[]

for i in range(n):
    print("here", script[i])
    s, r = Verify_and_decrypt(g1, h, i, commit, script[i], script2[i], f)
    shares.append([(i+1), s])
# print(Verify_proof(g, PKs[1], pkd, group.deserialize(script[1][1]), group.deserialize(script[1][2]), kds[1]))
    e2 = time.time()
    print(e2-e)

print("?", interpolate_at_x1(shares[:f+1], 0, ZR(0)))

#prove: g ** SK == PK[pid] and PK[dealer] ** SK == kds[pid]
def generage_proof(g, ski, pki, pkd, kdi):
    # g_e = group.hash(dumps(v), G)
    # g_e = G1.hash(dumps(C))
    # print(type(sk), sk)
    # kdi = pkd ** ski
    # pkd = g ** skd
    s = ZR.rand()
    # s = group.random(ZR)
    # s = ZR.rand()
    h = g ** s
    h_e = pkd ** s
    c = ZR.hash(dumps([serialize(g), serialize(pkd), serialize(h),
                          serialize(pki), serialize(kdi), serialize(h_e)]))
    # c = ZR.hash(dumps([g, pk, h, g_e, g_i_e, h_e]))
    z = s + int(ski) * int(c)

    # if pid == 0: print("", z)
    return c, z, serialize(kdi)





def Verify_proof(g, pki, pkd, proof, script_i, commit_i):
    # g_e = group.hash(dumps(v), G)
    c, z, kdi_s = proof
    kdi = deserialize(kdi_s)

    h = (g ** z) / (pki ** c)
    h_e = (pkd ** z) / (kdi ** c)
    # assert c == ZR.hash(dumps([g, pk, h, g_e, g_i_e, h_e]))
    try:
        # Verify NIZK proof
        assert c == ZR.hash(dumps([serialize(g), serialize(pkd), serialize(h),
                                  serialize(pki), serialize(kdi), serialize(h_e)]))
        # decrypt and verify commit
        si = AESCipher(str(kdi)).decrypt(script_i)
        assert g1 ** ZR(si) == commit_i
    except Exception as e:
        traceback.print_exc(e)
        return False
    return True



#complain

# proof = generage_proof(g1, SKs[0], PKs[0], PKs[dealer], kds[0])
# print(Verify_proof(g1, PKs[0], PKs[dealer], proof,  script[0], commit[0]))