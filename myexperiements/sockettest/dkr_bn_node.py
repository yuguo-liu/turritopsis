from gevent import monkey; monkey.patch_all(thread=False)

import random
from typing import  Callable
import os
import pickle
from gevent import time
from adkr.keyrefersh.core.n_adkr_bn import Adkrround
from myexperiements.sockettest.make_random_tx import tx_generator
from multiprocessing import Value as mpValue
from coincurve import PrivateKey, PublicKey
from adkr.acss.core.polynomial_charm import polynomials_over
# from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
from utils.core.betterpairing import G1, G2, ZR, pair
from utils.core.serializer import serialize, deserialize
def load_key(id, N_all, N_g):

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
        with open(os.getcwd() + '/keys-' + str(N_g) + '/' + 'thSK2-' + str(id) + '.key', 'rb') as fp:
            thsk = (pickle.load(fp))

    with open(os.getcwd() + '/keys-' + str(N_g) + '/' + 'thPK2-' + '.key', 'rb') as fp:
        thpk = (pickle.load(fp))

    thpks = []
    for i in range(N_g):
        with open(os.getcwd() + '/keys-' + str(N_g) + '/' + 'thPK2-' + str(i) + '.key', 'rb') as fp:
            thpks.append([(i+1), (pickle.load(fp))])

    return sPK2s, ePKs, sSK2, eSK, thsk, thpks, thpk

class ADKRBNNode (Adkrround):

    def __init__(self, sid, id, B, l, f, N_g, N, reconfig, bft_from_server: Callable, bft_to_client: Callable, ready: mpValue, stop: mpValue, K=3, mode='debug', mute=False, debug=False, tx_buffer=None):
        self.sPK2s, self.ePKs, self.sSK2, self.eSK, self.thsk, self.thpks, self.thpk = load_key(id, N, N_g)
        # print(len(self.sPK2s))
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
        print(N_g, self.f_g, self.l_g)
        self.recon = reconfig
        B_m = self.l_g * 2

        g2 = G2.hash(b'1')
        g1 = G1.hash(b'2')
        for i in range(N_g):
            self.C_g.append(i)
        print(self.C_g)
        # list
        l_num = int(l)
        self.add_list = []
        self.leave_list = []
        t = int(K / self.recon) + 1
        for i in range(N_g, N_g + l_num * t + 1):
            self.add_list.append(i)
        C_t = []
        for item in self.C_g:
            C_t.append(item)
        for i in range(l_num * t + 1):
            C_t.append(N_g + i)
            self.leave_list.append(C_t[0])
            C_t.remove(C_t[0])

        print(self.add_list)
        print(self.leave_list)
        if id in self.C_g:
            Adkrround.__init__(self, sid, id, B, B_m, l, f, self.C_g, self.N, reconfig, self.leave_list, g1, 'b',
                             self.sPK2s, self.sSK2, self.ePKs, self.eSK, self.thpk, self.thpks, self.thsk,
                             self.send, self.recv, K=K, mute=mute, debug=debug)
        else:
            Adkrround.__init__(self, sid, id, B, B_m, l, f, self.C_g, self.N, reconfig, self.leave_list, g1, 'b',
                             self.sPK2s, self.sSK2, self.ePKs, self.eSK, self.thpk, 0, 0,
                             self.send, self.recv, K=K, mute=mute, debug=debug)

    def run(self):

        pid = os.getpid()
        self.logger.info('node %d\'s starts to run consensus on process id %d' % (self.id, pid))


        while not self.ready.value:
            time.sleep(1)
            #gevent.sleep(1)

        self.run_bft()
        print(self.id, "set stop as true")
        self.stop.value = True

