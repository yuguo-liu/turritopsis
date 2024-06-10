from gevent import monkey; monkey.patch_all(thread=False)
import sys
import json
import logging
import os
import traceback, time
import gevent
import pickle
import numpy as np
from collections import namedtuple
from collections import defaultdict
from enum import Enum
from gevent.event import Event
from gevent import Greenlet
from gevent.queue import Queue

from speedmvba_dy.core.spbc_ec_dy import strongprovablebroadcast

from pickle import dumps, loads
from honeybadgerbft.exceptions import UnknownTagError
import hashlib
import dill
import statistics
from charm.toolbox.ecgroup import ECGroup
# from charm.toolbox.pairinggroup import PairingGroup, G1, G2, ZR, pair

# group = PairingGroup('BN254')
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

def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()

class BroadcastTag(Enum):
    ADKR_NEW = 'ADKR_NEW'
    ADKR_OLD = 'ADKR_OLD'


BroadcastReceiverQueues = namedtuple(
    'BroadcastReceiverQueues', ('ADKR_NEW', 'ADKR_OLD'))


def broadcast_receiver_loop(recv_func, recv_queues):
    while True:
        gevent.sleep(0)
        try:
            sender, (tag, msg) = recv_func()
        except Exception as e:
            continue
            # print('recv_sd', sender, tag)
        if tag not in BroadcastTag.__members__:
            # TODO Post python 3 port: Add exception chaining.
            # See https://www.python.org/dev/peps/pep-3134/
            raise UnknownTagError('Unknown tag: {}! Must be one of {}.'.format(
                tag, BroadcastTag.__members__.keys()))
        recv_queue = recv_queues._asdict()[tag]

        try:
            recv_queue.put_nowait((sender, msg))
        except AttributeError as e:
            print("error", sender, (tag, msg))
            traceback.print_exc(e)


class SPBChigh():

    def __init__(self, sid, pid, N, f, K, g1, g2, sPK, sSK, thpk, thpks, thsk, send, recv, mute=False, debug=None):
        self.sid = sid
        self.id = pid
        self.N = N
        self.f = f
        self.sPKS = sPK
        self.sSK = sSK
        self.thpks = thpks
        self.thpk = thpk
        self.thsk = thsk
        self._send = send
        self._recv = recv
        self.C_o = [i for i in range(N)]
        self.C_n = [i for i in range(N)]
        self.logger = set_consensus_log(pid)
        self.data_recv = Queue()
        self.data = defaultdict(lambda :list())
        self.K = K
        self.s_time = 0
        self.e_time = 0
        self.mute = mute
        self.debug = debug
        self.leave_signal = Event()
        self.g1 = g1
        self.send = send


    def run_bft(self):
        """Run the Dumbo protocol."""


        sid = self.sid
        pid = self.id

        adkr_old_recv = Queue()
        adkr_new_recv = Queue()

        recv_queues = BroadcastReceiverQueues(
            ADKR_OLD=adkr_old_recv,
            ADKR_NEW=adkr_new_recv
        )

        bc_recv_loop_thread = Greenlet(broadcast_receiver_loop, self._recv, recv_queues)
        bc_recv_loop_thread.start()

        # print("new nodes", self.id, "start to parsing configuration.")

        self.s_time = time.time()
        if self.logger != None:
            self.logger.info('Node %d starts to run at time:' % self.id + str(self.s_time))

        print(self.id, "start to run")
        s_time = time.time()

        def adkr_old_send(k, o):
            self.send(k, ('ADKR_OLD', o))

        def adkr_new_send(k, o):
            self.send(k, ('ADKR_NEW', o))
        my_input = Queue()
        decide = Queue()
        t = None
        if pid in self.C_o:
            if self.debug:
                t = gevent.spawn(strongprovablebroadcast, self.sid, pid, self.N, self.f, 0, self.C_o, self.sPKS, self.sSK, 1,
                                 my_input.get, decide.put_nowait, adkr_old_recv.get, adkr_old_send, 0, logger=self.logger, predicate=lambda x: True)
            else:
                t = gevent.spawn(strongprovablebroadcast, self.sid, pid, self.N, self.f, 0, self.C_o, self.sPKS, self.sSK, 1,
                                 my_input.get, decide.put_nowait, adkr_old_recv.get, adkr_old_send, 0, logger=self.logger, predicate=lambda x: True)

        my_input.put_nowait(b'lalalalalala')
        t.join()
        e_time = time.time()
        print(pid, decide.get())
        self.logger.info('run spbc_ec taking %f sec' % (e_time - s_time))
        print('run spbc_ec round taking %f sec' % (e_time - s_time))

        bc_recv_loop_thread.kill()
