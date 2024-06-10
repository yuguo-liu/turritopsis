# coding=utf-8
import time
from collections import defaultdict

import gevent
import zfec
import hashlib
import math
# from pypairing import G1, ZR
from charm.toolbox.ecgroup import ECGroup, G, ZR

from pickle import dumps, loads
from adkr.keyrefersh.core.poly_misc_charm import interpolate_g_at_x
# from adkg.utils.poly_misc import interpolate_g1_at_x
import traceback
def hash(x):
    assert isinstance(x, (str, bytes))
    try:
        x = x.encode()
    except AttributeError:
        pass
    return hashlib.sha256(x).digest()


def thresholdcoin(sid, pid,  N, f, l, C, g, v, PKs, SK, receive, send):
    """ACSS with dcr

    :param int pid: ``0 <= pid < N``
    :param int N:  at least 3
    :param int f: fault tolerance, ``N >= 3f + 1``
    :param receive: :func:`receive()` blocks until a message is
        received; message is of the form::

            (i, (tag, ...)) = receive()

        where ``tag`` is one of ``{"VAL", "ECHO", "READY"}``
    :param send: sends (without blocking) a message to a designed
        recipient ``send(i, (tag, ...))``

    :return str: ``m`` after receiving :math:`2f+1` ``READY`` messages
        and :math:`N-2f` ``ECHO`` messages



    """
    group = ECGroup(714)


    # assert N >= 3*f + 1
    # assert f >= 0
    # assert 0 <= dealer < N
    # assert 0 <= pid < N
    CoinyThreshold = f + 1
    # group = EC25519
    # print("g:", g)
    def generage_proof(g, pk, sk, v):
        g_e = group.hash(dumps(v), G)
        # g_e = G1.hash(dumps(C))
        # print(type(sk), sk)
        g_i_e = g_e ** sk
        s = group.random(ZR)
        # s = ZR.rand()
        h = g ** s
        h_e = g_e ** s
        c = group.hash(dumps([group.serialize(g), group.serialize(pk), group.serialize(h),
                              group.serialize(g_e), group.serialize(g_i_e), group.serialize(h_e)]), ZR)
        # c = ZR.hash(dumps([g, pk, h, g_e, g_i_e, h_e]))
        z = s + int(sk) * int(c)
        # if pid == 0: print("", z)
        return group.serialize(g_i_e), group.serialize(c), group.serialize(z)

    def Verify_proof(g, pk, v, c, z, g_i_e):
        g_e = group.hash(dumps(v), G)
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

    g_i_e_r, c_r, z_r = (generage_proof(g, PKs[C.index(pid)][1], SK, v))
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
            (_, (g_i_e_r, c_r, z_r)) = msg
            g_i_e = group.deserialize(g_i_e_r)
            c = group.deserialize(c_r)
            z = group.deserialize(z_r)
            try:
                Verify_proof(g, PKs[C.index(sender)][1], v, c, z, g_i_e)
            except Exception as e:
                # print("Failed to validate coin message:", e)
                traceback.print_exc(e)
                continue
            coinSender.add(sender)
            coinshare.append([sender+1, g_i_e])
            if len(coinSender) == CoinyThreshold:
                coin = interpolate_g_at_x(coinshare, 0, group.init(G))
                coin_int = int.from_bytes(group.serialize(coin), byteorder='big')
                # print(pid, "the coin value in view = ", coin_int)

                return coin_int
