from gevent import monkey; monkey.patch_all(thread=False)

import random
from typing import  Callable
import os
import pickle
from gevent import time
from adkr_hbacss.high_threshold_adkg.adkr_hbacss_high import Adkrhbacss
from myexperiements.sockettest.make_random_tx import tx_generator
from multiprocessing import Value as mpValue
from coincurve import PrivateKey, PublicKey
from adkr.acss.core.polynomial_charm import polynomials_over
from utils.core.betterpairing import G2, G1
from utils.core.serializer import serialize, deserialize
import logging

def set_consensus_log(id: int):
    logger = logging.getLogger("consensus-node-"+str(id))
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s %(filename)s [line:%(lineno)d] %(funcName)s %(levelname)s %(message)s ')
    if 'log' not in os.listdir(os.getcwd()):
        os.mkdir(os.getcwd() + '/log')
    full_path = os.path.realpath(os.getcwd()) + '/log/' + "consensus-node-"+str(id) + ".log"
    file_handler = logging.FileHandler(full_path)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger

def load_key(id, N):

    ePKs = []
    for i in range(N):
        with open(os.getcwd() + '/keys-' + str(N) + '/' + 'ePK2-' + str(i) + '.key', 'rb') as fp:
            ePKs.append(deserialize(pickle.load(fp)))

    with open(os.getcwd() + '/keys-' + str(N) + '/' + 'eSK2-' + str(id) + '.key', 'rb') as fp:
        eSK = pickle.load(fp)

    thsk = 0
    thpk = 0
    with open(os.getcwd() + '/keys-' + str(N) + '/' + 'thSK2-' + str(id) + '.key', 'rb') as fp:
        thsk = pickle.load(fp)

    with open(os.getcwd() + '/keys-' + str(N) + '/' + 'thPK2' + '.key', 'rb') as fp:
        thpk = deserialize(pickle.load(fp))

    thpks = []
    for i in range(N):
        with open(os.getcwd() + '/keys-' + str(N) + '/' + 'thPK2-' + str(i) + '.key', 'rb') as fp:
            thpks.append(deserialize(pickle.load(fp)))

    return ePKs, eSK, thsk, thpks, thpk

class ADKRHBNode(Adkrhbacss):

    def __init__(self, sid, id, f, N, K, bft_from_server: Callable, bft_to_client: Callable,
                 ready: mpValue, stop: mpValue, mode='debug', mute=False, debug=False):
        self.ePKs, self.eSK, self.thsk, self.thpks, self.thpk = load_key(id, N)
        # print(len(self.sPK2s))
        self.sid = sid
        self.id = id
        self.bft_from_server = bft_from_server
        self.bft_to_client = bft_to_client
        self.send = lambda j, o: self.bft_to_client((j, o))
        self.recv = lambda: self.bft_from_server()
        self.ready = ready
        self.stop = stop
        self.mode = mode
        self.N = N
        self.f = f
        self.K = K
        self.g2 = G2.hash(b'1')
        self.g1 = G1.hash(b'2')
        self.h = G1.hash(b'3')
        self.C_o = [i for i in range(N)]
        self.C_n = [i for i in range(N)]
        Adkrhbacss.__init__(self, sid, id, N, f, K, self.g1, self.g2, self.h, self.ePKs, self.eSK, self.thpk, self.thpks, self.thsk,
                          self.send, self.recv,  mute=mute, debug=debug)
    def run(self):

        pid = os.getpid()
        self.logger.info('node %d\'s starts to run consensus on process id %d' % (self.id, pid))


        while not self.ready.value:
            time.sleep(1)
            #gevent.sleep(1)

        self.run_bft()
        print(self.id, "set stop as true")
        self.stop.value = True

