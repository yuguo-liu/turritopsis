from gevent import monkey; monkey.patch_all(thread=False)

import random
import numpy as np
from typing import  Callable
import os
import pickle
from gevent import time
from speedydumbo_dy.core.speedydumbo_dy import SpeedyDumbo
from myexperiements.sockettest.make_random_tx import tx_generator
from multiprocessing import Value as mpValue
from coincurve import PrivateKey, PublicKey
from charm.toolbox.ecgroup import ECGroup, G, ZR
from adkr.acss.core.polynomial_charm import polynomials_over
group = ECGroup(714)
import hashlib, pickle
def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()

def load_key(id, N_all, N_g, l):
    sPK2s = []
    for i in range(N_all):
        with open(os.getcwd() + '/keys-' + str(N_g) + '/' + 'sPK2-' + str(i) + '.key', 'rb') as fp:
            sPK2s.append(PublicKey(pickle.load(fp)))
    ePKs = []
    for i in range(N_all):
        with open(os.getcwd() + '/keys-' + str(N_g) + '/' + 'ePK1-' + str(i) + '.key', 'rb') as fp:
            ePKs.append(pickle.load(fp))

    with open(os.getcwd() + '/keys-' + str(N_g) + '/' + 'sSK2-' + str(id) + '.key', 'rb') as fp:
        sSK2 = PrivateKey(pickle.load(fp))

    with open(os.getcwd() + '/keys-' + str(N_g) + '/' + 'eSK1-' + str(id) + '.key', 'rb') as fp:
        eSK = pickle.load(fp)
    thsk = 0
    if id < N_g:
        with open(os.getcwd() + '/keys-' + str(N_g) + '-' + str(l) + '/' + 'thSK1-' + str(id) + '.key', 'rb') as fp:
            thsk = group.deserialize(pickle.load(fp))

    with open(os.getcwd() + '/keys-' + str(N_g) + '-' + str(l) + '/' + 'thPK1-' + '.key', 'rb') as fp:
        thpk = group.deserialize(pickle.load(fp))

    thpks = []
    for i in range(N_g):
        with open(os.getcwd() + '/keys-' + str(N_g) + '-' + str(l) + '/' + 'thPK1-' + str(i) + '.key', 'rb') as fp:
            thpks.append([(i+1), group.deserialize(pickle.load(fp))])

    return sPK2s, ePKs, sSK2, eSK, thsk, thpks, thpk

class SDumboDYNode (SpeedyDumbo):

    def __init__(self, sid, id, B, l, f, N_g, N, reconfig, bft_from_server: Callable, bft_to_client: Callable, ready: mpValue, stop: mpValue, K=3, m=0, mode='debug', mute=False, debug=False, tx_buffer=None):
        self.sPK2s, self.ePKs, self.sSK2, self.eSK, self.thsk, self.thpks, self.thpk = load_key(id, N, N_g, l)
        print(len(self.sPK2s))
        self.g = group.hash(123, G)
        self.bft_from_server = bft_from_server
        self.bft_to_client = bft_to_client
        self.send = lambda j, o: self.bft_to_client((j, o))
        self.recv = lambda: self.bft_from_server()
        self.ready = ready
        self.stop = stop
        self.mode = mode
        self.C_g = []
        self.N = N
        self.l_g = int(l)
        self.f_g = f
        self.malicious = 0
        print(N_g, self.f_g, self.l_g)
        self.recon = reconfig
        B_m = (self.l_g) * 2

        for i in range(N_g):
            self.C_g.append(i)
        print(self.C_g)
        # list
        l_num = int(l)
        print(l_num, type(l_num))
        self.add_list = []
        self.leave_list = []
        t = int(K / self.recon)
        for i in range(N_g, N_g + l_num * t):
            self.add_list.append(i)
        C_t = []
        for item in self.C_g:
            C_t.append(item)
        for i in range(l_num * t):
            C_t.append(N_g + i)
            self.leave_list.append(C_t[0])
            C_t.remove(C_t[0])

        print(self.add_list)
        print(self.leave_list)
        print("debug is ", debug)
        if m > 0:
            a = hash(m)
            np.random.seed(int.from_bytes(a, byteorder='big') % 1000)

            c_old = [i for i in range(N_g)]
            c_new = [i + l for i in range(N_g)]
            pi = np.random.permutation([i for i in c_old])
            l_node = [i for i in range(l)]
            print("malicious in old", pi[:f])
            count = 0
            for i in pi[:f]:
                if i in l_node:
                    count += 1
            pi2 = np.random.permutation([i for i in list(set(c_new) - set(c_old))])
            print("malicious in old", pi2[:(count)])
            if id in pi[:f] or id in pi2[:(count)]:
                self.malicious = 1
                print("i am malicious", id)

        if id in self.C_g:
            SpeedyDumbo.__init__(self, sid, id, B, B_m, l, f, self.C_g, self.N, reconfig, self.leave_list, self.g, 's',
                             self.sPK2s, self.sSK2, self.ePKs, self.eSK, self.thpk, self.thpks, self.thsk,
                             self.send, self.recv, K=K, mute=mute, debug=debug, malicious=self.malicious)
        else:
            SpeedyDumbo.__init__(self, sid, id, B, B_m, l, f, self.C_g, self.N, reconfig, self.leave_list, self.g, 's',
                             self.sPK2s, self.sSK2, self.ePKs, self.eSK, 0, 0, 0,
                             self.send, self.recv, K=K, mute=mute, debug=debug, malicious=self.malicious)
    def prepare_bootstrap(self):
        self.logger.info('node id %d is inserting dummy payload TXs' % (self.id))
        if self.mode == 'test' or 'debug': #K * max(Bfast * S, Bacs)
            tx = tx_generator(250)  # Set each dummy TX to be 250 Byte
            k = 0

            for i in range(len(self.add_list)):
                SpeedyDumbo.submit_mem(self, self.add_list[i], 'J')
                SpeedyDumbo.submit_mem(self, self.leave_list[i], 'L')

            # SpeedyDumbo.submit_mem(self, 10, 'J')
            # SpeedyDumbo.submit_mem(self, 2, 'L')
            for e in range(self.K+1):
                for r in range(self.B):
                    SpeedyDumbo.submit_tx(self, tx.replace(">", hex(e) + hex(r)  + ">"))
                    k += 1
                    if r % 50000 == 0:
                        self.logger.info('node id %d just inserts 50000 TXs' % (self.id))

        else:
            pass
            # TODO: submit transactions through tx_buffer
        self.logger.info('node id %d completed the loading of dummy TXs' % (self.id))

    def run(self):

        pid = os.getpid()
        self.logger.info('node %d\'s starts to run consensus on process id %d' % (self.id, pid))


        self.prepare_bootstrap()

        while not self.ready.value:
            time.sleep(1)
            #gevent.sleep(1)

        self.run_bft()
        print(self.id, "set stop as true")
        self.logger.info('set stop as true')
        self.stop.value = True

