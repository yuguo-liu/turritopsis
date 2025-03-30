import json
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


BS = 16


def pad(s):
    print(s)
    print((16 - len(s) % BS))
    print(chr(16 - len(s) % BS))
    return s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
a = "aaaaaaaaaaaa"

b = json.dumps(a)
print(type(b), b)
print("?", pad(b))