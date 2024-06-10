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

from adkr.adkr_high.adkg_adp_op.adkg_adkr_old_op import ADKR_old_c


from pickle import dumps, loads
from honeybadgerbft.exceptions import UnknownTagError
import hashlib
import psutil
import dill
import statistics
# from charm.toolbox.ecgroup import ECGroup
from charm.toolbox.pairinggroup import PairingGroup, G1, G2, ZR, pair

group = PairingGroup('BN254')
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
    ADKR_COUNT = 'ADKR_COUNT'


BroadcastReceiverQueues = namedtuple(
    'BroadcastReceiverQueues', ('ADKR_NEW', 'ADKR_OLD', 'ADKR_COUNT'))


def broadcast_receiver_loop(recv_func, recv_queues):
    while True:
        # gevent.sleep(0)
        try:
            sender,( r, (tag,  msg)) = recv_func()
        except Exception as e:
            continue
            # print('recv_sd', sender, tag)
        if tag not in BroadcastTag.__members__:
            # TODO Post python 3 port: Add exception chaining.
            # See https://www.python.org/dev/peps/pep-3134/
            raise UnknownTagError('Unknown tag: {}! Must be one of {}.'.format(
                tag, BroadcastTag.__members__.keys()))
        recv_queue = recv_queues._asdict()[tag]
        if tag not in {BroadcastTag.ADKR_COUNT.value}:
            recv_queue = recv_queue[r]
        try:
            recv_queue.put_nowait((sender, msg))
        except AttributeError as e:
            print("error", sender, (tag, msg))
            traceback.print_exc(e)

class Adkgadphigh():

    def __init__(self, sid, pid, N, f, K, g1, g2, ePK, eSK, thpk, thpks, thsk, send, recv, mute=False, debug=None):
        self.sid = sid
        self.id = pid
        self.N = N
        self.f = f
        self.ePKS = ePK
        self.eSK = eSK
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

        round = 2
        adkr_old_recv = [Queue() for _ in range(round)]
        adkr_new_recv = [Queue() for _ in range(round)]
        adkr_count_recv = Queue()

        recv_queues = BroadcastReceiverQueues(
            ADKR_OLD=adkr_old_recv,
            ADKR_NEW=adkr_new_recv,
            ADKR_COUNT=adkr_count_recv
        )
        bc_recv_loop_thread = Greenlet(broadcast_receiver_loop, self._recv, recv_queues)
        bc_recv_loop_thread.start()

        # print("new nodes", self.id, "start to parsing configuration.")

        self.s_time = time.time()
        if self.logger != None:
            self.logger.info('Node %d starts to run at time:' % self.id + str(self.s_time))

        print(self.id, "start to run")
        trific_io = psutil.net_io_counters()[:2]

        for r in range(round):
            s_time = time.time()
            def adkr_old_send(k, o):
                self.send(k, (r, ('ADKR_OLD', o)))

            def adkr_new_send(k, o):
                self.send(k, (r, ('ADKR_NEW', o)))
            t = None
            if self.debug:
                t = gevent.spawn(ADKR_old_c, self.sid + 'ADKR', pid, self.C_o, self.C_n, self.f, self.K, self.g1,
                            self.thpk, self.thpks, self.thsk,
                            self.ePKS, self.eSK, adkr_old_send, adkr_new_send, adkr_old_recv[r].get, logger=self.logger)
            else:
                t = gevent.spawn(ADKR_old_c, self.sid + 'ADKR', pid, self.C_o, self.C_n, self.f, self.K, self.g1,
                             self.thpk, self.thpks, self.thsk,
                             self.ePKS, self.eSK, adkr_old_send, adkr_new_send, adkr_old_recv[r].get, logger=self.logger)

            t.join()
            e_time = time.time()
            self.logger.info('run adkr taking %f sec' % (e_time - s_time))
            print('run adkr round taking %f sec' % (e_time - s_time))
        e_time = time.time()
        trific_io_new = psutil.net_io_counters()[:2]
        diff = trific_io_new[0]-trific_io[0], trific_io_new[1]-trific_io[1]

        self.send(0, (-1, ('ADKR_COUNT', (e_time - s_time, diff))))
        tt = time.time()
        if self.id == 0:
            co = 0
            co_n = 0
            bi = 0
            m = 2 * 1024 * 1024
            print("=======================")
            self.logger.info('========================')
            while True:
                sender, (ti, b) = adkr_count_recv.get()
                co += ti
                co_n += 1
                print(sender, ":", ti, b)

                self.logger.info('node: %d\ttime: %f\t traffic:%f, %f' % (sender, ti, b[0] / m, b[1] / m))
                if co_n == self.N:
                    print("")
                    print("avg:", co / self.N)
                    self.logger.info('avg:%f' % (co / self.N))
                    self.logger.info('========================')
                    break
                if time.time()-tt>10:
                    break
        else:
            gevent.sleep(5)
        bc_recv_loop_thread.kill()
