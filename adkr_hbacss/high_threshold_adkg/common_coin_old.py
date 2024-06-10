import gevent
from gevent import monkey; monkey.patch_all(thread=False)

import logging
from collections import defaultdict
from gevent import Greenlet
from gevent.queue import Queue
import hashlib
from utils.core.betterpairing import G2, G1, ZR
from adkr.keyrefersh.core.poly_misc_bn import interpolate_g1_at_x
from pickle import dumps, loads
from utils.core.serializer import serialize
import traceback
logger = logging.getLogger(__name__)


class CommonCoinFailureException(Exception):
    """Raised for common coin failures."""
    pass


def hash(x):
    return hashlib.sha256(x).digest()

def shared_coin(sid, pid, N, f, l, C, g1, PKs, SK, receive, broadcast,  single_bit=False, logger=None):
    """A shared coin based on threshold signatures

    :param sid: a unique instance id
    :param pid: my id number
    :param N: number of parties
    :param f: fault tolerance, :math:`f+1` shares needed to get the coin
    :param PK: ``th-PublicKey``
    :param SK: ``th-PrivateKey``
    :param broadcast: broadcast channel
    :param receive: receive channel
    :param single_bit: is the output coin a single bit or not ?
    :return: a function ``getCoin()``, where ``getCoin(r)`` blocks
    """
    received = defaultdict(dict)
    coinshare = defaultdict(lambda: list())
    outputQueue = defaultdict(lambda: Queue(1))
    coin_request = defaultdict(lambda: list())
    def generage_proof(g, pk, sk, v):


        g_e = G1.hash(dumps(int(v)))
        # g_e = G1.hash(dumps(C))
        # print(g_e)
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

    def _recv():
        while True:     # main receive loop
            sender, msg = receive()

            (_, r) = msg
            coin_request[r].append(sender)

            if len(coin_request[r])==f+1:
                g_i_e_r, c_r, z_r = (generage_proof(g1, PKs[C.index(pid)], SK, r))

                broadcast(('COIN', r, (g_i_e_r, c_r, z_r)))


    #greenletPacker(Greenlet(_recv), 'shared_coin', (pid, N, f, broadcast, receive)).start()
    Greenlet(_recv).start()
    gevent.sleep(100)
    return


