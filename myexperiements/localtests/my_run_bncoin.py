import unittest
import gevent
import random
import gevent
from gevent import Greenlet
from gevent.queue import Queue
from adkr.keyrefersh.core.thresholdcoin_bn import thresholdcoin_bn
from g_thresh_gen import generate_thre_new
from utils.core.betterpairing import G2, G1
g21 = G2.hash(b'1')
g11 = G1.hash(b'2')
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
            # print ('BC   %8s [%2d -> %2d] %2.1f' % (o[0], i, j, delay*1000))
            gevent.spawn_later(delay, queues[j].put, (i,o))
            #queues[j].put((i, o))
        def _bc(o):
            for j in range(N): _send(j, o)
        return _bc

    def makeRecv(j):
        def _recv():
            (i,o) = queues[j].get()
            # print ('RECV %8s [%2d -> %2d]' % (o[0], i, j))
            return (i,o)
        return _recv

    return ([makeBroadcast(i) for i in range(N)],
            [makeRecv(j)      for j in range(N)])


### Test
def _test_commoncoin(N=4, f=1, seed=None):
    # Generate keys
    g1, g2, thpk, thpks, thsks = generate_thre_new(N, f)
    sid = 'sidA'
    # Test everything when runs are OK
    #if seed is not None: print 'SEED:', seed
    rnd = random.Random(seed)
    router_seed = rnd.random()
    # print(router_seed)
    C = [i for i in range(N)]
    sends, recvs = simple_router(N, seed=seed)
    threads2 = []
    for i in range(N):
        t2 = Greenlet(thresholdcoin_bn, sid, i, N, f, 0, C, g1, router_seed*100, thpks, thsks[i], recvs[i], sends[i])
        t2.start()
        threads2.append(t2)
    gevent.joinall(threads2)
    for t2 in threads2:
        print("print t2", t2.value%2)
    return True


def test_commoncoin():
    for i in range(10):
        _test_commoncoin()


if __name__ == "__main__":
    test_commoncoin()
