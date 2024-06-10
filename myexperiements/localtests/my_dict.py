import time
from collections import defaultdict
import random
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
from utils.core.betterpairing import dotprod, inner_product
import phe
# from adkr.keyrefersh.core.poly_misc_bn import interpolate_g1_at_x

from utils.core.serializer import deserialize
from ipcl_python import PaillierKeypair, PaillierEncryptedNumber
from utils.core.betterpairing import mulexp
from utils.core.betterpairing import G2, G1, ZR
from utils.core.merkleTree import encode,decode
from utils.core.pok import pok_Verify, proof_of_knowledge
from utils.core.degreecheck import check_degree, gen_dual_code
from adkr.acss.core.polynomial_pairing import polynomials_over_BN
from adkr.keyrefersh.core.poly_misc_bn import interpolate_at_x1, interpolate_g1_at_x
from adkr.acss.core.polynomial_pairing import polynomials_over_BN


N=64
f = 21
g2 = G2.hash(b'1')
g1 = G1.hash(b'2')
h = G1.hash(b'3')
acss_share = [[None for _ in range(N)] for _ in range(N)]
m = 1
for d in range(N):
    poly = polynomials_over_BN(ZR)
    r = ZR.rand()
    phi = poly.random(f, m)
    phi2 = poly.random(f, r)
    phib = poly.random(f, m)
    phib2 = poly.random(f, r)
    commits = []
    # commit0 = (g ** phi.coeffs[0])*(g2 ** phi.coeffs[0])
    for i in range(f + 1):
        commits.append(serialize((g1 ** phi.coeffs[i]) * (h ** phi2.coeffs[i])))
    for i in range(f + 1):
        commits.append(serialize((g1 ** phib.coeffs[i]) * (h ** phib2.coeffs[i])))
    for j in range(N):
        acss_share[j][d] = ((phi(j+1), phi2(j+1)), (phib(j+1), phib2(j+1)))


st = time.time()
select_index = set()
for i in range(43):
    select_index.add(i)
for j in range(N):
    for i in range(N):
        if i not in select_index:
            acss_share[j][i] = ((ZR(0), ZR(0)), (ZR(0), ZR(0)))

hm_1 = np.array([[ZR(i + 1) ** j for j in range(N)] for i in range(f + 1)])
hm_2 = np.array([[ZR(i + 1) ** j for j in range(N)] for i in range(f)])
mat1, mat2 = hm_1.tolist(), hm_2.tolist()
z_shares = [ZR(0)] * (2*f + 1)
r_shares = [ZR(0)] * (2*f + 1)
t1 = time.time()
for i in range(f + 1):
    # print("??????????", acss_share)
    secrets = [acss_share[0][j][0][0] for j in range(N)]
    randomness = [acss_share[0][j][0][1] for j in range(N)]
    z_shares[i] = inner_product(mat1[i], secrets)
    r_shares[i] = inner_product(mat1[i], randomness)

for i in range(f, 2*f):
    secrets = [acss_share[0][j][1][0] for j in range(N)]
    randomness = [acss_share[0][j][1][1] for j in range(N)]
    # print(i + 1, i - (t), mat2[i - (t)])
    z_shares[i + 1] = inner_product(mat2[i - f], secrets)
    r_shares[i + 1] = inner_product(mat2[i - f], randomness)
poly = polynomials_over_BN(ZR)
phi = poly(z_shares)
phi_r = poly(r_shares)
share_list = []
random_list = []
output_key = defaultdict()
for i in range(f+1):
    share_list.append([i + 1, phi(i+1)])
    random_list.append([i + 1, phi_r(i+1)])
if len(share_list) == f + 1:
    zi = interpolate_at_x1(share_list[:f + 1], 0, ZR(0))
    zi_s = interpolate_at_x1(random_list[:f + 1], 0, ZR(0))
    output_key['sk'] = zi
    output_key['sk_s'] = zi_s
    # print("z value", zi, zi_s)
    proof = proof_of_knowledge(g1, g1 ** zi, zi)
    proof_s = proof_of_knowledge(h, h ** zi_s, zi_s)
u = [g1 ** i for i in range(N)]
v = [g1 ** i for i in range(N)]
c_coeffs = [G1.identity()] * (2 * f + 1)
c_shares = [ZR(0)] * (N)
for i in range(f + 1):
    c_coeffs[i] = mulexp(u, mat1[i])
for i in range(f, 2 * f):
    c_coeffs[i + 1] = mulexp(v, mat2[i - f])
# print("u", u)

for i in range(N):
    re = G1.identity()
    for k in range(2 * f + 1):
        re *= c_coeffs[k] ** ((i + 1) ** k)
    c_shares[i] = re

for i in range(N):
    t1 = time.time()
    pok_Verify(g1 ** zi, g1, proof)
    pok_Verify(h ** zi_s, h, proof_s)
    print(time.time()-t1)
print(time.time()-st)