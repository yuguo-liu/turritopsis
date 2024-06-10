import random

import gevent
from gevent import Greenlet
from gevent.queue import Queue

from utils.core.disperse import disperse
from utils.core.retrieve import retrieve


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
            if j == -1:
                for t in range(N):
                    gevent.spawn_later(delay, queues[t].put, (i, o))
                # print('BC   %8s [%2d -> %2d] %2.1f' % (o[0], i, j, delay*1000))
            else:
                gevent.spawn_later(delay, queues[j].put, (i, o))
            # queues[j].put((i, o))
        return _send

    def makeRecv(j):
        def _recv():
            (i,o) = queues[j].get()
            # print ('RECV %8s [%2d -> %2d]' % (o[0], i, j))
            return (i,o)
        return _recv

    return ([makeSend(i) for i in range(N)],
            [makeRecv(j) for j in range(N)])




def _test_rbc1(N=4, f=1, leader=None, seed=None):
    # Test everything when runs are OK
    #if seed is not None: print 'SEED:', seed
    sid = 'sidA'
    # Note thld siganture for CBC has a threshold different from common coin's

    rnd = random.Random(seed)
    router_seed = rnd.random()
    if leader is None: leader = rnd.randint(0,N-1)
    sends, recvs = simple_router(N, seed=seed)
    threads = []
    leader_input = Queue(1)
    for i in range(N):
        input = leader_input.get if i == leader else None
        t = Greenlet(disperse, sid, i, N, f, leader, input, recvs[i], sends[i])
        t.start()
        threads.append(t)

    m = b"Hello! This is a test message."
    leader_input.put(m)
    gevent.joinall(threads)
    getchunk = [Queue(1) for _ in range(N)]
    i=0
    for t in threads:
        print("here", t.value)
        getchunk[i].put(t.value)
        i +=1



    sends2, recvs2 = simple_router(N, seed=seed)
    threads2 = []
    for i in range(N):
        t2 = Greenlet(retrieve, i, sid, N, f, getchunk[i].get_nowait, recvs2[i], sends2[i])
        t2.start()
        print(i, "start")
        threads2.append(t2)

    gevent.joinall(threads2)
    for t2 in threads2:
        print("print t2", t2.value)


def test_rbc1(N, f, seed):
    _test_rbc1(N=N, f=f, seed=seed)


if __name__ == '__main__':
    test_rbc1(4, 1, None)
