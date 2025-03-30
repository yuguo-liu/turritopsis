
import pickle
import os
from charm.toolbox.ecgroup import ECGroup, G
from charm.toolbox.pairinggroup import PairingGroup
from adkr.acss.core.polynomial_charm import polynomials_over
from adkr.acss.core.polynomial_pairing import polynomials_over_BN as polynomials_over_BN_N
from utils.core.polynomial_pairing_charm import polynomials_over_BN
from utils.core.betterpairing import G1 as G11, G2  as G21, ZR as ZR1
group = ECGroup(714)
g = group.hash(123, G)
group2 = PairingGroup('BN254')
g1 = group2.deserialize(b'1:If6Twx6TSz+MkjMqbBaM8hMRMa5KbNfPgsHzJWcVxo4A')
g1.initPP()
g2 = group2.deserialize(
    b'2:BB7S0EzUecv5S+ULwaHA6YS7SVQLSUsD9EPrNdt0ZuoBj6iA7b7R5q0OiNsk28D0/iMgOmHu8H4L1gIAxRTMiAA=')
g2.initPP()
g21 = G21.hash(b'1')
g11 = G11.hash(b'2')
print(g11, g21)
def trusted_key_gen(N=17, f=5, l=2, seed=None):

    thpk, thpks, thsks = generate_thre_s(N, f)
    thpk2, thpks2, thsks2 = generate_thre_bn(N, f)

    if 'keys' not in os.listdir(os.getcwd()):
        os.mkdir(os.getcwd() + '/keys')

    for i in range(N):
        with open(os.getcwd() + '/keys-'+str(N)+'-' + str(l)+'/' + 'thPK1-' + str(i) + '.key', 'wb') as fp:
            pickle.dump(thpks[i], fp)
        with open(os.getcwd() + '/keys-'+str(N)+'-' + str(l)+'/'+ 'thPK2-' + str(i) + '.key', 'wb') as fp:
            pickle.dump(thpks2[i], fp)

    with open(os.getcwd() + '/keys-'+str(N)+'-' + str(l)+'/' + 'thPK1-' + '.key', 'wb') as fp:
            pickle.dump(thpk, fp)
    with open(os.getcwd() + '/keys-'+str(N)+'-' + str(l)+'/' + 'thPK2-' + '.key', 'wb') as fp:
            pickle.dump(thpk2, fp)

    for i in range(N):
        with open(os.getcwd() + '/keys-'+str(N)+'-' + str(l)+'/' + 'thSK1-' + str(i) + '.key', 'wb') as fp:
            pickle.dump(thsks[i], fp)
        with open(os.getcwd() + '/keys-'+str(N)+'-' + str(l)+'/' + 'thSK2-' + str(i) + '.key', 'wb') as fp:
            pickle.dump(thsks2[i], fp)


def generate_thre_s(N=4, f=1):
    thsks = []
    thpks = []
    poly = polynomials_over()
    secret = 1
    phi = poly.random(f, secret)
    for i in range(N):
        thsks.append(group.serialize(phi(i + 1)))
        thpks.append(group.serialize(g ** phi(i + 1)))
    thpk = group.serialize(g ** secret)
    return thpk, thpks, thsks

def generate_thre_bn(N = 6, f = 1):
    thsks = []
    thpks = []
    poly = polynomials_over_BN()
    secret = 1
    phi = poly.random(f, secret)
    for i in range(N):
        thsks.append(group2.serialize(phi(i + 1)))
        thpks.append(group2.serialize(g1 ** phi(i + 1)))
    thpk = group2.serialize(g1 ** secret)

    return thpk, thpks, thsks

def generate_thre_bn2(N = 6, f = 1):
    thsks = []
    thpks = []
    poly = polynomials_over_BN()
    secret = 1
    phi = poly.random(f, secret)
    for i in range(N):
        thsks.append(phi(i + 1))
        thpks.append(g1 ** phi(i + 1))
    thpk = g1 ** secret

    return thpk, thpks, thsks

def generate_thre_bn_g2(N = 6, f = 1):
    thsks = []
    thpks = []
    poly = polynomials_over_BN()
    secret = 1
    phi = poly.random(f, secret)
    for i in range(N):
        thsks.append(phi(i + 1))
        thpks.append(g2 ** phi(i + 1))
    thpk = g2 ** secret

    return thpk, thpks, thsks

def generate_thre_new(N = 6, f = 1):
    thsks = []
    thpks = []
    poly = polynomials_over_BN_N(ZR1)
    secret = 1
    phi = poly.random(f, secret)
    for i in range(N):
        thsks.append(phi(i + 1))
        # print(type(thsks[i]))
        thpks.append(g11 ** phi(i + 1))
    thpk = g11 ** secret

    return g11, g21, thpk, thpks, thsks

def trusted_nonthre_key_gen(N=17, f=8):
    SKs = []
    PKs = []
    for i in range(N):
        SKs.append(ZR1.rand())
        PKs.append(g11 ** SKs[i])
    return PKs, SKs
if __name__ == '__main__':

    trusted_key_gen()
