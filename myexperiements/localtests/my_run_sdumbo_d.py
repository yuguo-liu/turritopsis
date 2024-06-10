import time
import gevent
from gevent import monkey
from gevent.queue import Queue
from crypto.threshsig.generate_keys import dealer
from crypto.threshenc import tpke
from crypto.ecdsa.ecdsa import pki
from charm.toolbox.ecgroup import ECGroup, G, ZR
from adkr.acss.core.polynomial_charm import polynomials_over
import phe
from gevent import monkey; monkey.patch_all(thread=False)

import random
from typing import  Callable
import os
import pickle
from gevent import time
from speedydumbo_dy.core.speedydumbo_dy import SpeedyDumbo
from myexperiements.sockettest.make_random_tx import tx_generator
from multiprocessing import Value as mpValue
from coincurve import PrivateKey, PublicKey
monkey.patch_all(thread=False)

group = ECGroup(714)

def simple_router(N, maxdelay=0.01, seed=None):
    """Builds a set of connected channels, with random delay

    :return: (receives, sends)
    """
    rnd = random.Random(seed)

    queues = [Queue() for _ in range(N)]
    _threads = []

    def makeSend(i):
        def _send(j, o):
            delay = rnd.random() * maxdelay
            if not i % 3:
                delay *= 0
            gevent.spawn_later(delay, queues[j].put_nowait, (i,o))
        return _send

    def makeRecv(j):
        def _recv():
            (i,o) = queues[j].get()
            # print(j, "recv", (i,o))
            #print 'RECV %8s [%2d -> %2d]' % (o[0], i, j)
            return (i,o)
        return _recv

    return ([makeSend(i) for i in range(N)],
            [makeRecv(j) for j in range(N)])

def prepare_bootstrap(self):
    self.logger.info('node id %d is inserting dummy payload TXs' % (self.id))
    tx = tx_generator(250)  # Set each dummy TX to be 250 Byte
    k = 0
    # SpeedyDumbo.submit_mem(self, 4, 'J')
    # SpeedyDumbo.submit_mem(self, 3, 'L')
    for _ in range(self.K):
        for r in range(self.B):
            SpeedyDumbo.submit_tx(self, tx.replace(">", hex(r) + ">"))
            k += 1
            if r % 50000 == 0:
                self.logger.info('node id %d just inserts 50000 TXs' % (self.id))

        # TODO: submit transactions through tx_buffer
    self.logger.info('node id %d completed the loading of dummy TXs' % (self.id))


def load_key(N_all, N_g):

    sPK2s = []
    for i in range(N_all):
        with open(os.getcwd() + '/keys-' + str(N_g) + '/' + 'sPK2-' + str(i) + '.key', 'rb') as fp:
            sPK2s.append(PublicKey(pickle.load(fp)))
    ePKs = []
    for i in range(N_all):
        with open(os.getcwd() + '/keys-' + str(N_g) + '/' + 'ePK1-' + str(i) + '.key', 'rb') as fp:
            ePKs.append(pickle.load(fp))
    sSK2s = []
    for i in range(N_all):
        with open(os.getcwd() + '/keys-' + str(N_g) + '/' + 'sSK2-' + str(i) + '.key', 'rb') as fp:
            sSK2s.append(PrivateKey(pickle.load(fp)))
    eSKs = []
    for i in range(N_all):
        with open(os.getcwd() + '/keys-' + str(N_g) + '/' + 'eSK1-' + str(i) + '.key', 'rb') as fp:
            eSKs.append(pickle.load(fp))
    thsks = []
    for i in range(N_g):
        with open(os.getcwd() + '/keys-' + str(N_g) + '/' + 'thSK1-' + str(i) + '.key', 'rb') as fp:
            thsks.append(group.deserialize(pickle.load(fp)))

    with open(os.getcwd() + '/keys-' + str(N_g) + '/' + 'thPK1-' + '.key', 'rb') as fp:
        thpk = group.deserialize(pickle.load(fp))

    thpks = []
    for i in range(N_g):
        with open(os.getcwd() + '/keys-' + str(N_g) + '/' + 'thPK1-' + str(i) + '.key', 'rb') as fp:
            thpks.append([(i+1), group.deserialize(pickle.load(fp))])

    return sPK2s, ePKs, sSK2s, eSKs, thsks, thpks, thpk


### Test asynchronous common subset
def tsdumbo(N_all, N_g, f, l, B, K, recon, seed=None):
    sid = 'sidA'
    C_g = []
    for i in range(N_g):
        C_g.append(i)
    # Generate threshold sig keys for thld f+1
    add_list = []
    leave_list = []
    t = int(K / recon) + 1
    for i in range(N_g, N_g + l * t + 1):
        add_list.append(i)
    C_t = []
    for item in C_g:
        C_t.append(item)
    for i in range(l * t + 1):
        C_t.append(N_g + i)
        leave_list.append(C_t[0])
        C_t.remove(C_t[0])

    g = group.hash(123, G)

    # Generate threshold enc keys
    sPK2s, ePKs, sSK2s, eSKs, thsks, thpks, thpk = load_key(N_all, N_g)

    rnd = random.Random(seed)
    #print 'SEED:', seed
    router_seed = rnd.random()
    sends, recvs = simple_router(N_all, seed=router_seed)

    sdumbos = [None] * N_all
    threads = [None] * N_all

    # This is an experiment parameter to specify the maximum round number 
    for i in range(N_all):
        if i in range(len(C_g)):
            sdumbos[i] = SpeedyDumbo(sid, i, B, l*2, l, f, C_g, N_g, recon, leave_list, g, 's',
                                 sPK2s, sSK2s[i], ePKs, eSKs[i], thpk, thpks, thsks[i],
                                 sends[i], recvs[i], K)
        else:
            sdumbos[i] = SpeedyDumbo(sid, i, B, l*2, l, f, C_g, N_g, recon, leave_list, g, 's',
                                 sPK2s, sSK2s[i], ePKs, eSKs[i], 0, 0, 0,
                                 sends[i], recvs[i], K)


        tx = tx_generator(250)  # Set each dummy TX to be 250 Byte
        k = 0

        for j in range(len(add_list)):
            sdumbos[i].submit_mem(add_list[j], 'J')
            sdumbos[i].submit_mem(leave_list[j], 'L')

        # SpeedyDumbo.submit_mem(self, 10, 'J')
        # SpeedyDumbo.submit_mem(self, 2, 'L')
        for e in range(K+1):
            for r in range(B):
                sdumbos[i].submit_tx(tx.replace(">", hex(e) + hex(r)  + ">"))
                k += 1



    for i in range(N_all):
        threads[i] = gevent.spawn(sdumbos[i].run_bft)



    print('start the test...')
    time_start = time.time()

    #gevent.killall(threads[N-f:])
    #gevent.sleep(3)
    #for i in range(N-f, N):
    #    inputs[i].put(0)
    gevent.joinall(threads)
    try:
        # outs = [threads[i].get() for i in range(N)]
        print("outs")
        # Consistency check
        # assert len(set(outs)) == 1
    except KeyboardInterrupt:
        gevent.killall(threads)
        raise

    time_end = time.time()
    print('complete the test...')
    print('time cost: ', time_end-time_start, 's')


def t_sdumbo():
    tsdumbo(17, 17, 4, 2, 1000, 100, 200)


if __name__ == '__main__':
    t_sdumbo()
