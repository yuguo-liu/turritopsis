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
from pickle import dumps, loads
import phe
from adkr.acss.core.polynomial_charm import polynomials_over
from adkr.acss.core.polynomial_pairing import polynomials_over_BN
from adkr.keyrefersh.core.poly_misc_bn import lagrange_x
group = PairingGroup('BN254')
# g1 = group.random(G1)
# g2 = group.random(G2)
# h1 = group.random(G2)
# u1 = group.random(G2)
n = 4
t = 1

g1 = group.deserialize(b'1:AN3vaywaAbtz9oSOehDxA8kBr3lnI6FftEfi+PCpsOwB')
g1.initPP()
g2 = group.deserialize(
    b'2:DQT2Rd58uiwgldvGY+ejPIhRHLkgon8ataszIFmQZoAWMWYFc53zBiE10qgdsBKRlcBgpraYIaJ1TbdKph8VGgA=')
g2.initPP()
h1 = group.deserialize(
    b'2:FEm/7O39fQLLEp6lQ1ySiom5RENmbCRg0WSWjGF0GIEJ47Oa8N6nwqUnVY6nIHXGBLS80RDhn6jfi7y/q33nRgE=')
h1.initPP()
u1 = group.deserialize(
    b'2:Blbg+VOpWJ9ZTDxtRgPI2/V0Ot9FFoAq3k2AwjVojGsPxx63BEd+ObaAFg9aaar7M+gC1o9BO1c0CqnfGpwe8gE=')
u1.initPP()
h2 = group.deserialize(b'2:D3osZABaoUHbAy2l0qHuHbH+WXkkqdYtMd4F3YbcOjMToCpn4aAGeeTt6JXYIf0PResVdiKhboXyrqsxmoFL4gE=')
h2.initPP()
h3 = group.deserialize(b'2:CNIvmNafzuJZyjds/DU31gTnjj9vYpvNPQZDZQITYsgQzMDKs7G9mApUCIVf5MJEdDupgN/MIa7Hf81zQgXdyAA=')
h3.initPP()
h4 = group.deserialize(b'2:A885/p3qo4CH9tmFvdXbTKYhpK/Ucdl1bPTXUw1duj0Y/1+lc1RmhuJAJtqcAUxl9kV7RsTjTuGOMtZ5EFxe6AA=')
h4.initPP()


def Deal(m, t, ek):
    poly = polynomials_over_BN()
    phi = poly.random(t, m)
    F = list()
    A = list()
    Y = list()
    for i in range(t+1):
        F.append(g1 ** phi.coeffs[i])
    for i in range(n):
        A.append(g1 ** phi(i+1))
        Y.append(ek[i] ** phi(i+1))
    u2 = u1 ** phi(0)
    return F, u2, A, Y


def Verify(ek, pvss, t):
    s = set()
    sx = list()
    rnd = random.Random()
    alpha = (int(rnd.random()) % n) + 1
    # print(alpha)
    F, u2, A, Y = pvss
    assert pair(F[0], u1) == pair(g1, u2)
    for i in range(n):
        assert pair(g1, Y[i]) == pair(A[i], ek[i])
        s.add(i+1)
        sx.append(i+1)
    out = group.init(G1)
    out_r = group.init(G1)
    for i in range(n):
        out *= (A[i] ** lagrange_x(s, sx[i], alpha))
    # print("left = ", out)
    for j in range(t+1):
        out_r *= F[j] ** (alpha ** j)
    # print("right = ", out_r)
    assert out == out_r
    return 1


def Aggregate(pvss1, pvss2):
    F = list()
    A = list()
    Y = list()
    F1, u12, A1, Y1 = pvss1
    F2, u22, A2, Y2 = pvss2
    for i in range(t+1):
        F.append(F1[i] * F2[i])
    for i in range(n):
        A.append(A1[i] * A2[i])
        Y.append(Y1[i] * Y2[i])
    u2 = u12 * u22
    return F, u2, A, Y

def Aggregate_set(scripts, num):
    F = list()
    A = list()
    Y = list()
    u2 = group.init(G2)
    for i in range(num):
        F1, u12, A1, Y1 = scripts[i]
        for j in range(t + 1):
            if i ==0:
                F.append(group.init(G1))
            F[j] *= F1[j]
        for j in range(n):
            if i == 0:
                A.append(group.init(G1))
                Y.append(group.init(G2))
            A[j] *= A1[j]
            Y[j] *= Y1[j]
        u2 *= u12
    return F, u2, A, Y

def ta(eks):
    scripts = defaultdict()
    for i in range(n):
        pvss = Deal(i, t, eks)
        print(Verify(eks, pvss, t))
        scripts[i] = pvss

    pvss = Aggregate_set(scripts, 4)
    print(Verify(eks, pvss, t))

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
    Sig = [(0, 0) for _ in range(n)]
    C[id] = g1 ** m
    # print("CID is", C[id])
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
    assert out == F[0]
    return 1

def Aggscripts(scripts, num):
    F = list()
    A = list()
    Y = list()
    u2 = group.init(G2)
    w = list()
    C = list()
    Sig = list()
    for i in range(num):
        C1, w1, Sig1, (F1, u12, A1, Y1) = scripts[i]
        for j in range(t + 1):
            if i == 0:
                F.append(group.init(G1))
            F[j] *= F1[j]
        for j in range(n):
            if i == 0:
                A.append(group.init(G1))
                Y.append(group.init(G2))
                w.append(0)
                C.append(1)
                Sig.append((0, 0))
            A[j] *= A1[j]
            Y[j] *= Y1[j]
            w[i] += w1[i]
            if C1[j] != 1 and C[j] == 1:
                C[j] = C1[j]
            if Sig1 != (0, 0) and Sig[j] == (0, 0):
                Sig[j] = Sig1[j]
        u2 *= u12
    return C, w, Sig, (F, u2, A, Y)




def k_g(script):
    C, w, Sig, pvss = script
    F, u2, A, Y = pvss
    out = group.init(G1)
    out2 = group.init(G2)
    sks = list()
    for i in range(n):
        if w[i]!=0:
            out *= C[i]
            out2 *= u2
        sks.append(Y[i] ** (dks[i] ** (-1)))

    pk = (out, out2)
    return pk, sks

"""
scripts = defaultdict()
for i in range(n):
    scripts[i] = Dealscript(i+1, i)
    print(Verifyscript(scripts[i]))

agg_s = Aggscripts(scripts, n)
print(Verifyscript(agg_s))
print(k_g(agg_s))
"""
