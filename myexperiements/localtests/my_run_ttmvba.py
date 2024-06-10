import random
import gevent
from gevent import Greenlet, time
from gevent.queue import Queue
from gevent import monkey
from crypto.threshsig.generate_keys import dealer
from crypto.ecdsa.ecdsa import pki
# from speedmbva.core.smvba import speedmvba
from utils.core.tthresholdmvba import tthresholdmvba
# from charm.toolbox.pairinggroup import PairingGroup, ZR as ZR1, G1, G2
from g_thresh_gen import generate_thre_new
from utils.core.betterpairing import G2, G1
g2 = G2.hash(b'1')
g1 = G1.hash(b'2')
# CBC
def simple_router(N, maxdelay=0.001, seed=None):
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


def _test_vaba(N=4, f=1, leader=None, seed=None):
    # Test everyth=ing when runs are OK
    rnd = random.Random()
    sid = 'M11231'+str(rnd.random())
    # Note thld siganture for CBC has a threshold different from common coin's
    _, _, thpk, thpks, thsks = generate_thre_new(N, f)

    s_time = time.time()
    # if leader is None: leader = rnd.randint(0, N-1)
    sends, recvs = simple_router(N, seed=seed)

    threads = []
    inputs = [Queue(1) for _ in range(N)]
    outputs = [Queue() for _ in range(N)]
    C = [i for i in range(N)]
    for i in range(N):
        msg = i
        inputs[i].put_nowait(str(msg).encode('utf-8'))
        print("Input to node %d has been provided" % i)

    for i in range(N):
        t = Greenlet(tthresholdmvba, sid, i, N, f, C, g1, thpks, thsks[i],
                     inputs[i].get, outputs[i].put_nowait, recvs[i], sends[i])
        t.start()
        threads.append(t)
        print("tMVBA at node %d has been instantiated" % i)

    try:
        outs = [outputs[i].get() for i in range(N)]

        try:
            gevent.joinall(threads)
            print(outs)
            e_time = time.time()
            print("running time:", e_time - s_time)
        except gevent.hub.LoopExit:
            pass
    except KeyboardInterrupt:
        gevent.killall(threads)
        raise

    # Assert the CBC-delivered values are same to the input
    # assert [t.value[0] for t in threads] == [m]*N
    # Assert the CBC-delivered authentications (i.e., signature) are valid
    # digest = PK.hash_message(str((sid, leader, m)))
    # assert [PK.verify_signature(t.value[1], digest) for t in threads] == [True]*N


def test_vaba(N, f, seed):
    for k in range(1):
        _test_vaba(N=N, f=f, seed=seed)


if __name__ == '__main__':
    test_vaba(7, 2, None)
