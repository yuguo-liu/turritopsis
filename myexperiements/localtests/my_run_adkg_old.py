import random
import time

import gevent
from gevent import Greenlet
from gevent.queue import Queue
from collections import defaultdict
from adkr.adkr_high.adkg_adp.adkg_adkr_old import ADKR_old_c
from adkr.adkr_high.core.adkr_new import adkr_new
import phe

from g_thresh_gen import generate_thre_new
from utils.core.betterpairing import G2, G1
g2 = G2.hash(b'1')
g1 = G1.hash(b'2')
### RBC
def simple_router(N, maxdelay=0.01, seed=None):
    """Builds a set of connected channels, with random delay
    @return (receives, sends)
    """
    rnd = random.Random(seed)
    #if seed is not None: print 'ROUTER SEED: %f' % (seed,)

    queues = [Queue() for _ in range(N)]

    def makeSend(i):
        def _send(j, o):
            delay = rnd.random() * maxdelay
            #print 'SEND %8s [%2d -> %2d] %.2f' % (o[0], i, j, delay)
            if j==-1:
                for t in range(N):
                    gevent.spawn_later(delay, queues[t].put, (i, o))
            elif j==-2:
                for t in range(N):
                    if t != i:
                        gevent.spawn_later(delay, queues[t].put, (i, o))
            else:
                gevent.spawn_later(delay, queues[j].put, (i,o))
            #queues[j].put((i, o))
        return _send

    def makeRecv(j):
        def _recv():
            (i,o) = queues[j].get()
            #print 'RECV %8s [%2d -> %2d]' % (o[0], i, j)
            return (i,o)
        return _recv

    return ([makeSend(i) for i in range(N)],
            [makeRecv(j) for j in range(N)])




def _test_rbc1(N=4, f=1, leader=None, seed=None):
    # Test everything when runs are OK
    #if seed is not None: print 'SEED:', seed
    sid = 'sidA'
    # Note thld siganture for CBC has a threshold different from common coin's
    # PK, SKs = dealer(N, N - f)
    _, _, thpk, thpks, thsks = generate_thre_new(N, 2*f)
    keypairs = [phe.paillier.generate_paillier_keypair(n_length=2048) for _ in range(N)]
    ePKs1, eSKs1 = [[keypairs[i][j] for i in range(N)] for j in range(2)]
    rnd = random.Random(seed)
    router_seed = rnd.random()
    C_o = [i for i in range(N)]
    C_n = C_o
    N_n = N
    f_n = f
    sends, recvs = simple_router(N, seed=seed)
    sends2, recvs2 = simple_router(N, seed=seed)
    threads = []
    leader_input = Queue(1)
    output = [Queue() for _ in range(N)]
    s = time.time()
    for i in range(N):

        t = gevent.spawn(ADKR_old_c, sid, i, C_o, C_n, f, 4, g1, thpk, thpks, thsks[i], ePKs1, eSKs1[i], sends[i], sends2[i], recvs[i])
        # t.start()
        threads.append(t)
    threads2 = []
    # for i in range(N):
    #     t2 = gevent.spawn(adkr_new, i, sid, C_n, N, N, f, f, 4, g1, ePKs1, eSKs1[i], recvs2[i])
        # t2.start()
    #     threads2.append(t2)
    # gevent.joinall(threads2)

    v = set()
    gevent.joinall(threads)
    for t in threads:
        v.add(t.get())
    print(len(v))
    print(time.time()-s)

def test_rbc1(N, f, seed):
    _test_rbc1(N=N, f=f, seed=seed)


if __name__ == '__main__':
    test_rbc1(4, 1, None)
