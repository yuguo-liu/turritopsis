import sys
sys.path.append("/home/hugo/turritopsis")
import random
import time

import gevent
from gevent import Greenlet
from gevent.queue import Queue

from speedmvba.core.spbc_ec import strongprovablebroadcast
from g_thresh_gen import generate_thre_new
from utils.core.betterpairing import G2, G1
from utils.core.bls_bn import sign, verify_share, verify_signature, hash_message, combine_shares
from myexperiements.sockettest.sdumbo_dy_node import load_key, hash
from crypto.ecdsa.ecdsa import ecdsa_vrfy

g2 = G2.hash(b'1')
g1 = G1.hash(b'2')


# CBC
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


def _test_spbc(N=7, f=2, leader=None, seed=None):
    # Test everything when runs are OK
    sid = 'sidA'
    # Generate threshold sig keys
    # _, _, thpk, thpks, thsks = generate_thre_new(N, 2*f)
    SK2s = []
    PK2s = None
    for id in range(N):
        PK2s, _, sk2, _, _, _, _ = load_key(id, N, N, 0)
        SK2s.append(sk2)

    rnd = random.Random(seed)
    router_seed = rnd.random()
    if leader is None: leader = rnd.randint(0, N-1)
    print("\033[30m[INFO]\033[0m  The leader is: ", leader)
    sends, recvs = simple_router(N, seed=seed)

    threads = []
    leader_input = Queue(1)
    output_list = Queue()
    C = [i for i in range(N)]
    s_t = time.time()
    for i in range(N):
        input = leader_input.get if i == leader else None
        # t = Greenlet(strongprovablebroadcast, sid, i, N, f, 0, C, thpk, thsks[i], leader, input, output_list.put_nowait, recvs[i], sends[i], 0)
        t = Greenlet(strongprovablebroadcast, sid, i, N, f, PK2s, SK2s[i], leader, input, output_list.put_nowait, recvs[i], sends[i], 0)
        t.start()
        threads.append(t)

    m = f"Hello! This is a test message from {leader}"
    print("\033[30m[INFO]\033[0m leader sends: ", m)
    leader_input.put(m)
    gevent.joinall(threads)
    for t in threads:
        print("\033[30m[INFO]\033[0m ", t.value)
        while output_list.qsize() > 0:
            print("\033[30m[INFO]\033[0m ---", output_list.get())
    # Assert the CBC-delivered values are same to the input
    assert [t.value[0] for t in threads] == [m]*N, "\033[31m[ERROR]\033[0m message is error"
    print("\033[32m[PASS]\033[0m received messages are correspond to the sent message")
    print(f"\033[30m[INFO]\033[0m broadcast time: {(time.time()-s_t) * 1000} ms")

    # Assert the CBC-delivered authentications (i.e., signature) are valid
    digest = hash(str((sid, m, "FINAL")))
    for t in threads:
        sigmas = t.value[1]
        for (k, sig) in sigmas:
            assert ecdsa_vrfy(PK2s[k], digest, sig), "\033[31m[ERROR]\033[0m signature is error"
    print("\033[32m[PASS]\033[0m signatures are valid")

def test_spbc(N, f, seed):
    _test_spbc(N=N, f=f, seed=seed)


if __name__ == '__main__':
    test_spbc(9, 2, None)
