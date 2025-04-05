# coding=utf-8
import time
from collections import defaultdict

import gevent
import zfec
import hashlib
import math
# from charm.toolbox.pairinggroup import PairingGroup, ZR, G1
from utils.core.betterpairing import ZR, G1
from pickle import dumps, loads
from adkr.keyrefersh.core.poly_misc_bn import interpolate_g1_at_x
# from adkg.utils.poly_misc import interpolate_g1_at_x
from utils.core.serializer import serialize

import traceback
def hash(x):
    assert isinstance(x, (str, bytes))
    try:
        x = x.encode()
    except AttributeError:
        pass
    return hashlib.sha256(x).digest()


def thresholdcoin_bn(sid, pid,  N, f, l, C, g1, v, PKs, SK, receive, send):
    """ACSS with dcr

    :param int pid: ``0 <= pid < N``
    :param int N:  at least 3
    :param int f: threshold
    :param receive: :func:`receive()` blocks until a message is
        received; message is of the form::

            (i, (tag, ...)) = receive()

        where ``tag`` is one of ``{"VAL", "ECHO", "READY"}``
    :param send: sends (without blocking) a message to a designed
        recipient ``send(i, (tag, ...))``

    :return str: ``m`` after receiving :math:`2f+1` ``READY`` messages
        and :math:`N-2f` ``ECHO`` messages



    """


    # assert N >= 3*f + 1
    # assert f >= 0
    # assert 0 <= dealer < N
    # assert 0 <= pid < N
    CoinyThreshold = f + 1
    # group = EC25519
    # print("g:", g)
    def generage_proof(g, pk, sk, v):


        g_e = G1.hash(dumps(int(v)))
        # g_e = G1.hash(dumps(C))
        g_i_e = g_e ** sk
        s = ZR.rand()
        # s = ZR.rand()
        h = g ** s
        h_e = g_e ** s
        c = ZR.hash(dumps([g, pk, h, g_e,g_i_e,h_e]))
        # c = ZR.hash(dumps([g, pk, h, g_e, g_i_e, h_e]))
        z = s + int(sk) * int(c)
        # if pid == 0: print("", z)
        return g_i_e, c, z

    def Verify_proof(g, pk, v, c, z, g_i_e):
        g_e = G1.hash(dumps(v))
        h = (g ** z) / (pk ** c)
        h_e = (g_e ** z) / (g_i_e ** c)
        # assert c == ZR.hash(dumps([g, pk, h, g_e, g_i_e, h_e]))
        try:
            # assert c == group.hash(dumps([group.serialize(g), group.serialize(pk), group.serialize(h),
            #                           group.serialize(g_e), group.serialize(g_i_e), group.serialize(h_e)]), ZR)

            assert h == (g ** z) / (pk ** c)
        except Exception as e:
            traceback.print_exc(e)
        return True

    # print(pid, PKs[C.index(pid)][1])

    g_i_e_r, c_r, z_r = (generage_proof(g1, PKs[C.index(pid)][1], SK, v))
    send(('coin', (g_i_e_r, c_r, z_r)))
    # print(pid, SK)
    coinSender = set()
    coinshare = []
    while True:  # main receive loop
        # print(pid, "start acss")
        sender, msg = receive()
        # print(pid, "recv", (sender, msg[0]))
        if msg[0] == 'coin':
            # Validation
            (_, (g_i_e, c, z)) = msg
            # g_i_e = group.deserialize(g_i_e_r)
            # c = group.deserialize(c_r)
            # z = group.deserialize(z_r)
            try:
                # s1 = time.time()
                Verify_proof(g1, PKs[C.index(sender)][1], v, c, z, g_i_e)
                # s2 = time.time()
                # print(s2-s1)
            except Exception as e:
                # print("Failed to validate coin message:", e)
                traceback.print_exc(e)
                continue
            coinSender.add(sender)
            coinshare.append([sender+1, g_i_e])
            if len(coinSender) == CoinyThreshold:
                coin = interpolate_g1_at_x(coinshare, 0, G1.identity())
                coin_int = int.from_bytes(hash(serialize(coin)), byteorder='big')
                print(pid, "the coin value in view = ", coin_int)

                return coin_int
