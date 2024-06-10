import unittest
import gevent
import random
from gevent.queue import Queue
from utils.core.common_coin_bn import shared_coin
from crypto.threshsig.boldyreva import dealer

import random
import gevent
from gevent import Greenlet
from gevent.queue import Queue
from adkr.keyrefersh.core.thresholdcoin_bn import thresholdcoin_bn
from g_thresh_gen import generate_thre_bn2
from charm.toolbox.pairinggroup import PairingGroup, ZR as ZR1, G1, G2
group2 = PairingGroup('BN254')
g1 = group2.deserialize(b'1:If6Twx6TSz+MkjMqbBaM8hMRMa5KbNfPgsHzJWcVxo4A')
g1.initPP()
g2 = group2.deserialize(
    b'2:BB7S0EzUecv5S+ULwaHA6YS7SVQLSUsD9EPrNdt0ZuoBj6iA7b7R5q0OiNsk28D0/iMgOmHu8H4L1gIAxRTMiAA=')
g2.initPP()
def simple_router(N, maxdelay=0.01, seed=None):
    """Builds a set of connected channels, with random delay
    @return (receives, sends)
    """
    rnd = random.Random(seed)
    #if seed is not None: print 'ROUTER SEED: %f' % (seed,)
    
    queues = [Queue() for _ in range(N)]

    def makeBroadcast(i):
        def _send(j, o):
            delay = rnd.random() * maxdelay
            #print 'BC   %8s [%2d -> %2d] %2.1f' % (o[0], i, j, delay*1000)
            gevent.spawn_later(delay, queues[j].put, (i,o))
            #queues[j].put((i, o))
        def _bc(o):
            for j in range(N): _send(j, o)
        return _bc

    def makeRecv(j):
        def _recv():
            (i,o) = queues[j].get()
            #print 'RECV %8s [%2d -> %2d]' % (o[0], i, j)
            return (i,o)
        return _recv

    return ([makeBroadcast(i) for i in range(N)],
            [makeRecv(j)      for j in range(N)])


### Test
def _test_commoncoin(N=4, f=1, seed=None):
    # Generate keys
    thpk, thpks, thsks = generate_thre_bn2(N, f)
    sid = 'sidA'
    # Test everything when runs are OK
    #if seed is not None: print 'SEED:', seed
    rnd = random.Random(seed)
    router_seed = rnd.random()
    sends, recvs = simple_router(N, seed=seed)
    C = [i for i in range(N)]

    coins = [shared_coin(sid, i, N, f, 0, C, g1, thpks, thsks[i], recvs[i], sends[i]) for i in range(N)]

    for i in range(10):
        threads = [gevent.spawn(c, int(i*router_seed*200)) for c in coins]
        gevent.joinall(threads)
        print(len(set([t.value for t in threads])))
        print(set([t.value for t in threads]))
    return True


def test_commoncoin():
    _test_commoncoin()


if __name__ == "__main__":
    test_commoncoin()
