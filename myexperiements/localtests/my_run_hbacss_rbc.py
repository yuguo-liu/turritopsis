import random
import time

import gevent
from gevent import Greenlet
from gevent.queue import Queue
from collections import defaultdict
from adkr.adkr_high.core.adkr_old import ADKR_old_c
from adkr.adkr_high.core.adkr_new import adkr_new
import phe
from adkr_hbacss.high_threshold_adkg.hbacss_rbc import completesecretsharing
from g_thresh_gen import generate_thre_new, trusted_nonthre_key_gen
from utils.core.betterpairing import G2, G1
from crypto.ecdsa.ecdsa import pki
g2 = G2.hash(b'1')
g1 = G1.hash(b'2')
h = G1.hash(b'3')
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




def _test_rbc1(N=4, f=1, dealer=None, seed=None):
    # Test everything when runs are OK
    #if seed is not None: print 'SEED:', seed
    sid = 'sidA'
    # Note thld siganture for CBC has a threshold different from common coin's
    # PK, SKs = dealer(N, N - f)
    PKs, SKs = pki(N)
    ePKs1, eSKs1 = trusted_nonthre_key_gen(N, f)
    _, _, thpk, thpks, thsks = generate_thre_new(N, f)
    # keypairs = [phe.paillier.generate_paillier_keypair(n_length=2048) for _ in range(N)]
    # ePKs1, eSKs1 = [[keypairs[i][j] for i in range(N)] for j in range(2)]
    rnd = random.Random(seed)
    router_seed = rnd.random()
    C_o = [i for i in range(N)]
    C_n = C_o
    N_n = N
    f_n = f
    sends, recvs = simple_router(N, seed=seed)


    threads = []
    leader_input = Queue(1)
    output = [Queue() for _ in range(N)]
    s = time.time()
    for i in range(N):
        input = leader_input.get if i == dealer else None
        # t = Greenlet(completesecretsharing, sid, i, N, f, C_o, N, f, C_n, g1, dealer, ePKs1, eSKs1[i], thpk, thsks[i],  input, output[i].put_nowait, recvs[i], sends[i], None)
        t = gevent.spawn(completesecretsharing, sid, i, N, f, C_o, N, f, C_n, g1, h, dealer, ePKs1, eSKs1[i], input, output[i].put_nowait, recvs[i], sends[i])
        threads.append(t)
    m = 100
    leader_input.put(m)
    gevent.joinall(threads)
    for i in range(N):
        # print(threads[i].get())
        print(output[i].get())
    print(time.time()-s)

def test_rbc1(N, f, dealer, seed):
    _test_rbc1(N=N, f=f, dealer=dealer, seed=seed)


if __name__ == '__main__':
    test_rbc1(16, 5, 1, None)
