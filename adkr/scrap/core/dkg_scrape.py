# coding=utf-8
import aifc
import time
from collections import defaultdict
import logging
import os
import gevent
import zfec
import hashlib
import math
from adkr.acss.core.reliablebroadcast import encode, decode, ceil, merkleTree, merkleVerify, getMerkleBranch
import random
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
from adkr.scrap.core.scrape import Deal, Verify, Aggregate_set
from pickle import dumps, loads
import phe
from adkr.acss.core.polynomial_charm import polynomials_over
from adkr.acss.core.polynomial_pairing import polynomials_over_BN
from adkr.keyrefersh.core.poly_misc_bn import lagrange_x
group = PairingGroup('BN254')
g1 = group.deserialize(b'1:If6Twx6TSz+MkjMqbBaM8hMRMa5KbNfPgsHzJWcVxo4A')
g1.initPP()
g2 = group.deserialize(
    b'2:BB7S0EzUecv5S+ULwaHA6YS7SVQLSUsD9EPrNdt0ZuoBj6iA7b7R5q0OiNsk28D0/iMgOmHu8H4L1gIAxRTMiAA=')
g2.initPP()
h1 = group.deserialize(
    b'2:BB6S0EzUecv5S+ULwaHA6YS7SVQLSUsD9EPrNdt0ZuoBj6iA7b7R5q0OiNsk28D0/iMgOmHu8H4L1gIAxRTMiAA=')
h1.initPP()
u1 = group.deserialize(
    b'2:BB6S0EzUecv5S+ULwaHA6YS0SVQLSUsD9EPrNdt0ZuoBj6iA7b7R5q0OiNsk28D0/iMgOmHu8H4L1gIAxRTMiAA=')
u1.initPP()
n = 4
t = 1


def keygen(n):
    dk = list()
    ek = list()
    ssk = list()
    vk = list()
    for i in range(n):
        dk.append(group.random(ZR))
        ek.append(h1 ** dk[i])
        ssk.append(group.random(ZR))
        vk.append(g1 ** ssk[i])
    return dk, ek, ssk, vk


dks, eks, ssks, vks = keygen(4)

def hash2(m):
    m = str(m)
    try:
        m = m.encode()
    except:
        pass
    return group.hash(m, G2)

def Dealscript(m, id):
    pvss = Deal(m, t, eks)
    C = [1 for _ in range(n)]
    w = [0 for _ in range(n)]
    Sig = [tuple() for _ in range(n)]
    C[id] = g1 ** m
    print("CID is", C[id])
    w[id] = 1
    sig1 = (hash2(C[id])) ** m
    sig2 = (hash2((vks[id], C[id]))) ** ssks[id]
    Sig[id] = (sig1, sig2)
    return C, w, Sig, pvss

def SoKVerify(Ci, sig, i):
    sig1, sig2 = sig
    assert pair(Ci, hash2(Ci)) == pair(g1, sig1)
    assert pair(vks[i], hash2((vks[i], Ci))) == pair(g1, sig2)
    return 1

def Verifyscript(script):
    C, w, Sig, pvss = script
    assert Verify(eks, pvss, t) == 1
    F, u2, A, Y = pvss
    out = group.init(G1)
    for i in range(n):
        if w[i] != 0:
            assert SoKVerify(C[i], Sig[i], i)
            out *= C[i]
    print(out)
    print(F[0])
    assert out == F[0]

    return 1


script = Dealscript(1, 0)
print(Verifyscript(script))

