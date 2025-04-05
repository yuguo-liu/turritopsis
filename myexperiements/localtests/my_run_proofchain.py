import time
from utils.core.bls_bn import sign as sign2, verify_share as vs2, hash_message as hash3
from charm.toolbox.ecgroup import ECGroup, G
from pickle import dumps, loads
import hashlib
import pickle
from crypto.ecdsa.ecdsa import pki
from crypto.ecdsa.ecdsa import ecdsa_vrfy, ecdsa_sign
from gevent import Greenlet
from gevent.queue import Queue
from collections import defaultdict
from gevent.event import Event
import sys
import dill
import phe
from utils.core.betterpairing import G1, G2, ZR, pair
import pickle
from g_thresh_gen import generate_thre_new
from collections import defaultdict
g2 = G2.hash(b'1')
g1 = G1.hash(b'2')
from utils.core.serializer import serialize, deserialize
groupec = ECGroup(714)
g = groupec.hash(123, G)


def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()


keypairs = [phe.paillier.generate_paillier_keypair(n_length=2048) for _ in range(4)]
pk, sk = [[keypairs[i][j] for i in range(4)] for j in range(2)]

r = pk[0].get_random_lt_n()

pk_digest = defaultdict(lambda: set())
pk_digest_bn = defaultdict(lambda: list())
pk_digest_bn2 = defaultdict(lambda: list())
secret = 1


proofchain = defaultdict(lambda: tuple())


def ec():

    for r in range(round):
        pk_shares_s = []
        pk_digest = defaultdict(lambda: set())
        C = [i+r for i in range(N)]
        rnd = pk[0].get_random_lt_n()
        c = pk[0].encrypt(int(r), r_value=rnd).ciphertext(be_secure=False)
        share_e = {}
        tpk = g ** r
        digest = hash(str(tpk))
        for i in range(f+1):
            sigma = ecdsa_sign(sSK2s[i], digest)
            pk_digest[digest].add((i, sigma))
        for i in range(N):
            pk_shares_s.append([C[i] + 1, groupec.serialize(tpk)])
            share_e[i] = c
            size1 = sys.getsizeof(c)
            size2 = sys.getsizeof(groupec.serialize(tpk))
            size3 =  sys.getsizeof(C)
        script = (pk_shares_s, share_e, groupec.serialize(tpk), C)
        print("script", (size2*N+size3*2))
        proofchain[r]=((script, pk_digest[digest]))

        del pk_digest
    # proofchain_d = dill.dumps(proofchain)

    size = sys.getsizeof(proofchain)
    print((size) / 1024)
    sigma = ecdsa_sign(sSK2s[0], digest)
    t1 = time.time()
    for i in range(round):
        for j in range(f+1):
            ecdsa_vrfy(sPK2s[0], digest, sigma)
    print(time.time()-t1)

# ec()
N=64
f =21
round =1000
sPK2s, sSK2s = pki(N)
C = [i for i in range(N)]
thsk_o = 11
tpk = g1 ** thsk_o
tpksize = sys.getsizeof(tpk)
digestm = G2.hash(serialize(tpk))
Sigma = digestm ** thsk_o
Sigmasize = sys.getsizeof(Sigma)
print(((tpksize+Sigmasize)*round)/1024)

tpk = g ** 11
digest = hash(str(tpk))
sigma = ecdsa_sign(sSK2s[0], digest)
sigmasize = sys.getsizeof(sigma)*(f+1)
c = pk[0].encrypt(int(1), r_value=1).ciphertext(be_secure=False)
size1 = sys.getsizeof(c)
size2 = sys.getsizeof(tpk)
size3 = sys.getsizeof(C)
# print(((size1*N+size2*N+size3*2+sigmasize)*120)/1024)
print(((size2+sigmasize)*round)/1024)

def ecsig(f, r):
    t1 = time.time()
    for i in range(r):
        for j in range(f + 1):
            ecdsa_vrfy(sPK2s[0], digest, sigma)
    print(time.time() - t1)

def bnsig(r):
    t1 = time.time()
    for i in range(r):
        assert pair(Sigma, g2) == pair(digestm, tpk)
    print(time.time() - t1)



thsk=11
thpk = g1 ** thsk
digestm = hash3(thpk)

sig = sign2(thsk, digestm)
def bn2sig(r):
    t1 = time.time()
    for i in range(r):
        assert vs2(thpk, sig, digestm)
    print(time.time() - t1)

thpksize = sys.getsizeof(thpk)
Sigmasize = sys.getsizeof(sig)

rset = [1, 40, 80, 150, 200, 300, 500, 1000]
for rr in rset:
    print(rr)
    bn2sig(rr)
    print(((thpksize + Sigmasize) * rr) / 1024)
    print("\n")
