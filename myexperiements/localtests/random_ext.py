import time
from collections import defaultdict

import gevent
from gevent.queue import Queue
from crypto.ecdsa.ecdsa import ecdsa_vrfy, ecdsa_sign
from crypto.ecdsa.ecdsa import pki
import hashlib, pickle
from pickle import dumps, loads
import pickle
import os
from crypto.threshsig.generate_keys import dealer
from g_thresh_gen import generate_thre_new
from g_thresh_gen import generate_thre_bn2
from utils.core.bls_bn2 import hash_message, sign, verify_share
from utils.core.serializer import serialize, serialize_G2, deseralize_G2
import numpy as np
from math import ceil
from utils.core.betterpairing import dotprod, inner_product, mulexp
from adkr.keyrefersh.core.poly_misc_bn import interpolate_at_x_b
import phe
from utils.core.serializer import deserialize
from adkr.acss.core.polynomial_pairing import polynomials_over_BN as polynomials_over_BN_N
from utils.core.betterpairing import G2, G1, ZR
g2 = G2.hash(b'1')
g1 = G1.hash(b'2')
h = G1.hash(b'2')
t = 5
n=16
deg = 2*t
zer = ZR(0)
sc = ceil((deg+1)/(t+1))+1
secrets = [[zer] * n for _ in range(sc - 1)]
randomness = [[zer] * n for _ in range(sc - 1)]
commits = [[G1.identity()] * n for _ in range(sc - 1)]
for idx in range(sc - 1):
    for node in range(n):
        secrets[idx][node] = ZR.rand()
        randomness[idx][node] = ZR.rand()
        commits[idx][node] = (g1 ** secrets[idx][node])*(h ** randomness[idx][node])
print(secrets)

def gen_vector(t, deg, n):
    coeff_1 = np.array([[ZR(i+1)**j for j in range(t+1)] for i in range(n)])
    coeff_2 = np.array([[ZR(i+1)**j for j in range(t+1, deg+1)] for i in range(n)])
    hm_1 = np.array([[ZR(i+1)**j for j in range(n)] for i in range(t+1)])
    hm_2 = np.array([[ZR(i+1)**j for j in range(n)] for i in range(deg-t)])
    rm_1 = np.matmul(coeff_1, hm_1)
    rm_2 = np.matmul(coeff_2, hm_2)
    return (rm_1.tolist(), rm_2.tolist())

def gen_vector2(t, deg, n):

    hm_1 = np.array([[ZR(i+1)**j for j in range(n)] for i in range(t+1)])
    hm_2 = np.array([[ZR(i+1)**j for j in range(n)] for i in range(deg-t)])
    print("hm1", hm_1.tolist())
    return (hm_1.tolist(), hm_2.tolist())

mat1, mat2 = gen_vector2(t, deg, n)
matrix = (mat1, mat2)
print(len(mat1), len(mat2))

z_shares = [zer] * (deg+1)
r_shares = [zer] * (deg+1)
print(mat1[0])
for i in range(t+1):
    print(i, mat1[i])
    z_shares[i] = inner_product(mat1[i], secrets[0])
    r_shares[i] = inner_product(mat1[i], randomness[0])
print("")
for i in range(t, deg):
    print(i+1, i-(t), mat2[i-(t)])
    z_shares[i+1] = inner_product(mat2[i-(t)], secrets[1])
    r_shares[i+1] = inner_product(mat2[i-(t)], randomness[1])
print("zshare", len(z_shares))

poly = polynomials_over_BN_N(ZR)
phi = poly(z_shares)
print(z_shares[0])
print(phi(0))


inner_product(matrix[0][0], secrets[0])
z_shares = [zer] * n
r_shares = [zer] * n
"""for i in range(n):
    for sec in range(sc - 1):
        print(i, sec)
        z_shares[i] = z_shares[i] + inner_product(matrix[sec][i], secrets[sec])
        r_shares[i] = r_shares[i] + inner_product(matrix[sec][i], randomness[sec])

print("Z", len(z_shares))"""
c_shares = [zer] * (deg+1)
for i in range(t+1):
    print(i, mat1[i])
    c_shares[i] = mulexp(commits[0], mat1[i])
for i in range(t, deg):
    print(i + 1, i - (t), mat2[i - (t)])
    c_shares[i + 1] = mulexp(commits[1], mat2[i - (t)])

