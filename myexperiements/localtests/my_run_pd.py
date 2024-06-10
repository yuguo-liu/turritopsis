import random

import gevent
from gevent import Greenlet
from gevent.queue import Queue
from collections import defaultdict
from crypto.threshsig.boldyreva import dealer
from utils.core.provabledispersal_g1 import provabledispersalbroadcast
from utils.core.recast_g1 import recastsubprotocol

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
    _, _, thpk, thpks, thsks = generate_thre_new(N, f)
    rnd = random.Random(seed)
    router_seed = rnd.random()
    if leader is None: leader = rnd.randint(0,N-1)
    sends, recvs = simple_router(N, seed=seed)
    threads = []
    leader_input = Queue(1)
    output = [Queue() for _ in range(N)]
    for i in range(N):
        input = leader_input.get if i == leader else None
        t = Greenlet(provabledispersalbroadcast, sid, i, N, f, thpk, thsks[i], leader, input, output[i].put_nowait, recvs[i], sends[i])
        t.start()
        threads.append(t)

    m = b"Hello! This is a test message."
    leader_input.put(m)
    gevent.joinall(threads)
    for t in threads:
        print(t.value)
    # assert [t.value[0] for t in threads] == [m]*N


    store = defaultdict()
    lock = defaultdict()
    getstore = [Queue(1) for _ in range(N)]
    getlock = [Queue(1) for _ in range(N)]
    for i in range(N):
        while not output[i].empty():
            get1 = output[i].get()
            # print(get1)
            if get1[0] == 'STORE':
                getstore[i].put(get1[1])
            elif get1[0] == 'LOCK':
                getlock[i].put(get1[1])
    sends2, recvs2 = simple_router(N, seed=seed)
    threads2 = []
    for i in range(N):
        t2 = Greenlet(recastsubprotocol, i, sid, N, f, thpk, thsks[i], getstore[i].get_nowait, getlock[i].get_nowait, recvs2[i], sends2[i])
        t2.start()
        threads2.append(t2)
    gevent.joinall(threads2)
    for t2 in threads2:
        print("print t2", t2.value)
def test_rbc1(N, f, seed):
    _test_rbc1(N=N, f=f, seed=seed)


if __name__ == '__main__':
    test_rbc1(4, 1, None)
