"""An implementation of (unique) threshold signatures based on
Gap-Diffie-Hellman Boldyreva, 2002 https://eprint.iacr.org/2002/118.pdf

Dependencies:
    Charm, http://jhuisi.github.io/charm/ a wrapper for PBC (Pairing
    based crypto)

"""
try:
    from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
    from base64 import encodestring, decodestring
    from operator import mul
    from functools import reduce
except Exception as err:
  print(err)
  exit(-1)


# group = PairingGroup('SS512')
# group = PairingGroup('MNT159')
group = PairingGroup('BN254')


ZERO = group.random(ZR, seed=59)*0
ONE = group.random(ZR, seed=60)*0+1

g1 = group.deserialize(b'1:If6Twx6TSz+MkjMqbBaM8hMRMa5KbNfPgsHzJWcVxo4A')
g1.initPP()
g2 = group.deserialize(
    b'2:BB7S0EzUecv5S+ULwaHA6YS7SVQLSUsD9EPrNdt0ZuoBj6iA7b7R5q0OiNsk28D0/iMgOmHu8H4L1gIAxRTMiAA=')
g2.initPP()

class TBLSPublicKey(object):
    """ """
    def __init__(self, l, k, VK, VKs):
        """ """
        self.l = l  # noqa: E741
        self.k = k
        self.VK = VK
        self.VKs = VKs

    def lagrange(self, S, j):
        """ """
        # Assert S is a subset of range(0,self.l)
        assert len(S) == self.k
        assert type(S) is set
        assert S.issubset(range(0, self.l))
        S = sorted(S)

        assert j in S
        assert 0 <= j < self.l
        num = reduce(mul, [0 - jj - 1 for jj in S if jj != j], ONE)
        den = reduce(mul, [j - jj for jj in S if jj != j], ONE)  # noqa: E272
        # assert num % den == 0
        return num / den

    def hash_message(self, m):
        """ """
        try:
            m = m.encode()
        except:
            pass
        return group.hash(m, G2)

    def verify_share(self, sig, i, h):
        """ """
        assert 0 <= i < self.l
        B = self.VKs[i]
        assert pair(g1, sig) == pair(B, h)
        return True

    def verify_signature(self, sig, h):
        """ """
        assert pair(g1, sig) == pair(self.VK, h)
        return True

    def combine_shares(self, sigs):
        """ """
        # sigs: a mapping from idx -> sig
        S = set(sigs.keys())
        assert S.issubset(range(self.l))

        res = reduce(mul,
                     [sig ** self.lagrange(S, j)
                      for j, sig in sigs.items()], 1)
        return res


class TBLSPrivateKey(TBLSPublicKey):
    """ """

    def __init__(self, l, k, VK, VKs, SK, i):
        """ """
        super(TBLSPrivateKey, self).__init__(l, k, VK, VKs)
        assert 0 <= i < self.l
        self.i = i
        self.SK = SK

    def sign(self, h):
        """ """
        return h ** self.SK


