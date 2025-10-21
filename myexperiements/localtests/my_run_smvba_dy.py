import sys
sys.path.append("/home/hugo/turritopsis")
import random
import gevent
from gevent import Greenlet, time
from gevent.queue import Queue
from gevent import monkey
from utils.core.betterpairing import G2, G1
g2 = G2.hash(b'1')
g1 = G1.hash(b'2')
from speedmvba.core.smvba_e import speedmvba
from myexperiements.sockettest.sdumbo_dy_node import load_key
from charm.toolbox.ecgroup import ECGroup, G
group = ECGroup(714)

monkey.patch_all(thread=False)

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


def _test_smbva(N=16, f=5, leader=None, seed=None):
    # Test everything when runs are OK
    # sid = 'SMVBA'
    # Note thld siganture for CBC has a threshold different from common coin's
    # g1, g2, thpk, thpks, thsks = generate_thre_new(N, 2*f)
    SK2s = []
    PK2s = None
    eSKs = []
    ePKs = None
    for id in range(N):
        PK2s, ePKs, sk2, eSK, _, _, _ = load_key(id, N, N, 0)
        SK2s.append(sk2)
        eSKs.append(eSK)
    C = [i for i in range(N)]
    s_time = time.time()
    sid = 'SMVBA'+str(random.Random(seed).random()*100)
    # if leader is None: leader = rnd.randint(0, N-1)
    sends, recvs = simple_router(N, seed=seed)

    threads = []
    inputs = [Queue(1) for _ in range(N)]
    outputs = [Queue() for _ in range(N)]
    def p(msg):
        return True

    for i in range(N):
        node_input = [i, (i+1)%N, (i+2)%N]
        inputs[i].put_nowait(node_input)
        print(f"\033[30m[INFO]\033[0m Input to node {i} has been provided as: {node_input}")

    for i in range(N):
        t = Greenlet(speedmvba, sid, i, N, f, PK2s, SK2s[i], 
                     inputs[i].get, outputs[i].put_nowait, recvs[i], sends[i], predicate=p)
        t.start()
        threads.append(t)
        print("\033[30m[INFO]\033[0m sMVBA at node %d has been instantiated" % i)

    try:
        outs = [outputs[i].get() for i in range(N)]

        try:
            gevent.joinall(threads)
            print("\033[36m[OUTPUTS]\033[0m Outputs: ", outs)
            e_time = time.time()
            print("\033[33m[TIME]\033[0m running time:", e_time - s_time)
            assert all(outs[0] == o for o in outs[1:]), "\033[31m[ERROR]\033[0m Agreement is not reached for different output"
            print("\033[32m[PASS]\033[0m All outputs are consistent, agreement passed")
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


def test_smvba(N, f, seed, r):
    for k in range(r):
        print("\033[35m[ROUND]\033[0m Round", k)
        _test_smbva(N=N, f=f, seed=seed)


if __name__ == '__main__':
    test_smvba(9, 2, None, 1)
