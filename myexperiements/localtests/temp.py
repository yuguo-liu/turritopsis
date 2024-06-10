import time
from pickle import dumps
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
import phe
from collections import defaultdict
from adkr.acss.core.polynomial_pairing import polynomials_over_BN
from adkr.keyrefersh.core.poly_misc_bn import interpolate_g1_at_x, interpolate_at_x
from pickle import dumps, loads
from operator import mul
from functools import reduce
from crypto.threshsig.boldyreva_254 import TBLSPublicKey, TBLSPrivateKey
group = PairingGroup('BN254')


def get_avss_params(n, t):
    s = time.time()
    # g1 = group.random(G1)
    # g2 = group.random(G2)
    # print(group.serialize(g2))
    keypairs = [phe.paillier.generate_paillier_keypair(n_length=2048) for _ in range(8)]
    ePK, eSK = [[keypairs[i][j] for i in range(8)] for j in range(2)]
    g1 = group.deserialize(b'1:If6Twx6TSz+MkjMqbBaM8hMRMa5KbNfPgsHzJWcVxo4A')
    g1.initPP()
    g2 = group.deserialize(
        b'2:BB7S0EzUecv5S+ULwaHA6YS7SVQLSUsD9EPrNdt0ZuoBj6iA7b7R5q0OiNsk28D0/iMgOmHu8H4L1gIAxRTMiAA=')
    g2.initPP()
    return ePK, eSK, g1, g2

def prove_knowledge_of_encrypted_dlog(g, x, pk, g_to_the_x=None):
    if g_to_the_x is None:
        Y = g ** x
    else:
        Y = g_to_the_x

    r = pk.get_random_lt_n()
    c = pk.encrypt(int(x), r_value=r).ciphertext(be_secure=False)
    # Todo: see if this limitation is libarary-specific. Maybe use a slightly larget N?
    u = pk.get_random_lt_n() // 3  # maximum valid value we can encrypt
    T = g ** u
    e = group.hash(dumps([pk, group.serialize(g), group.serialize(Y), c, group.serialize(T)]))
    z = u + int(e) * int(x)
    s = pk.get_random_lt_n()
    e_u = pk.encrypt(u, r_value=s)
    w = (pow(r, int(e), pk.nsquare) * s) % pk.nsquare
    proof = [group.serialize(T), z, e_u, w]
    return [group.serialize(Y), c, proof]


ZERO = group.random(ZR, seed=59)*0
ONE = group.random(ZR, seed=60)*0+1

n = 6
f = 1
ePK, eSK, g1, g2= get_avss_params(n, f)

C = [2, 3, 4, 5, 6, 7]


poly = polynomials_over_BN()

def get_dealer_msg(deg, secret, n):
    thsks = []
    thpks = []
    enthsks = []

    phi = poly.random(f, secret)
    for i in range(n):
        thsks.append(phi(C[i] + 1))
        # print(thsks[i])
        r = ePK[C[i]].get_random_lt_n()
        a = time.time()
        c = ePK[C[i]].encrypt(int(phi(C[i] + 1)), r_value=r).ciphertext(be_secure=False)
        b = time.time()
        print(b-a)
        enthsks.append(c)
        thpks.append([C[i]+1, g1 ** phi(C[i] + 1)])
    thpk = g1 ** secret
    assert interpolate_g1_at_x(thpks[:f+1], 0, group.init(G1, 1)) ==  thpk
    return thpks, enthsks, thpk


pk_shares_s = []
comms = defaultdict(lambda : list())
encs = defaultdict()

for j in range(n):
    secret = 1
    dealer = get_dealer_msg(f, secret, n)
    comms[j] = dealer[0]
    encs[j] = dealer[1]


out = {2, 3}
commit = {}
share_e = {}
pk_shares = []
desks = []
for i in range(n):
    commit[i] = group.init(G1)
    encn = ePK[C[i]].encrypt(int(0))
    share_e[i] = encn.ciphertext(be_secure=False)
    for j in out:
        commit[i] = commit[i] * comms[j][i][1]
        share_e[i] = encn._raw_add(encs[j][i], share_e[i])

    pk_shares.append([C[i] + 1, commit[i]])

thpk = interpolate_g1_at_x(pk_shares[:f+1], 0, group.init(G1))

assert thpk == g1 ** (f + 1)

for i in range(n):
    share_m = eSK[C[i]].raw_decrypt(share_e[i])
    desks.append([(C[i] + 1), share_m])

s = interpolate_at_x(desks[:f+1], 0, group.init(ZR))
print("point 0", s)

assert int(s) == (f + 1)


def hash2(m):
    try:
        m = m.encode()
    except:
        pass
    return group.hash(m, G2)


digest = hash2(str(1))
print(digest)

Sigma = []
for i in range(n):
    Sigma.append([C[i]+1, digest ** desks[i][1]])
    assert pair(g1, Sigma[i][1]) == pair(pk_shares[i][1], digest)

S = interpolate_g1_at_x(Sigma[:f + 1], 0, group.init(G2))
assert S == digest ** 2
s = time.time()
assert pair(g1, S) == pair(thpk, digest)
print(time.time()-s)