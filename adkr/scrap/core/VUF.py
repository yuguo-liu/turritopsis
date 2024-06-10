import time
from collections import defaultdict
import logging
import os
import gevent
import hashlib
from adkr.acss.core.reliablebroadcast import encode, decode, ceil, merkleTree, merkleVerify, getMerkleBranch
import random
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from adkr.scrap.core.scrape import keygen, Dealscript, Verifyscript, Aggscripts, k_g
from adkr.acss.core.polynomial_charm import polynomials_over
from adkr.acss.core.polynomial_pairing import polynomials_over_BN
from adkr.keyrefersh.core.poly_misc_bn import lagrange_x
group = PairingGroup('BN254')
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

dks, eks, ssks, vks = keygen(4)
scripts = defaultdict()
for i in range(n):
    scripts[i] = Dealscript(i+1, i)

    # print(Verifyscript(scripts[i]))

agg_s = Aggscripts(scripts, n)
print(Verifyscript(agg_s))
pk, sks = k_g(agg_s)

sk = h1 ** (1+2+3+4)

def hash1(m):
    m = str(m)
    try:
        m = m.encode()
    except:
        pass
    return group.hash(m, G1)

def vuf_eval(sk, m):
    z = hash1(m)
    return pair(z, sk)

def vuf_sign(sk, m):
    z = hash1(m)
    rnd = random.Random()
    alpha = (int(rnd.random()*10) % n) + 1
    beta = (int(rnd.random()*10) % n) + 1
    alpha = group.init(ZR, alpha)
    beta = group.init(ZR, beta)
    pi1 = g1 ** alpha
    pi2 = z ** alpha
    pi3 = g1 ** beta
    pi4 = z ** beta
    pi1_h = (h1 ** (-alpha)) * (h2 ** (-beta))
    pi2_h = (h3 ** (-alpha)) * ((h4 ** (-beta))) * sk
    return pi1, pi2, pi3, pi4, pi1_h, pi2_h

def vuf_signshare(ski, m):
    return vuf_sign(ski, m)

def vuf_combine(sigmaset):
    s = set()
    sx = list()
    for i in sigmaset.keys():
        s.add(i + 1)
        sx.append(i + 1)
    out = [group.init(G1), group.init(G1), group.init(G1), group.init(G1),
           group.init(G2), group.init(G2)]
    index = 0
    for i in sigmaset.keys():

        for j in range(6):
            out[j] *= (sigmaset[i][j] ** lagrange_x(s, sx[index], 0))
        index += 1
    return out

def vuf_derive(pk, m, sig):
    pi1, pi2, pi3, pi4, pi1_h, pi2_h = sig
    z = hash1(m)
    return pair(z, pi2_h) * pair(pi2, h3) * pair(pi4, h4)


def vuf_ver(pk, m, sig):
    A, u2 = pk
    pi1, pi2, pi3, pi4, pi1_h, pi2_h = sig
    z = hash1(m)
    assert group.init(GT, 1) == pair(g1, pi1_h) * pair(pi1, h1) * pair(pi3, h2)
    assert group.init(GT, 1) == pair(z, pi1_h) * pair(pi2, h1) * pair(pi4, h2)
    assert pair(A, h1) == pair(g1, pi2_h) * pair(pi1, h3) * pair(pi3, h4)
    return 1

sigmaset = defaultdict()
sigmaset2 = defaultdict()
for i in range(2):
    sigmaset[i] = vuf_sign(sks[i], 1)

for i in range(2, 4):
    sigmaset2[i] = vuf_sign(sks[i], 1)
sig = vuf_combine(sigmaset)
sig2 = vuf_combine(sigmaset2)
vuf_ver(pk, 1, sig)
vuf_ver(pk, 1, sig2)

print(vuf_derive(pk, 1, sig))
print(vuf_derive(pk, 1, sig2))