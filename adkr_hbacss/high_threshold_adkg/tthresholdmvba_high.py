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
from honeybadgerbft.core.reliablebroadcast import reliablebroadcast
from honeybadgerbft.exceptions import UnknownTagError
import hashlib
import dill
import statistics
from charm.toolbox.pairinggroup import PairingGroup, G1, G2, ZR, pair


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
        gevent.sleep(0)
        try:
            sender, (r, (tag, msg)) = recv_func()
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
            j, msg = msg
            recv_queue = recv_queue[r][j]
        try:

            recv_queue.put_nowait((sender, msg))
        except AttributeError as e:
            print("error", sender, (tag, msg))
            traceback.print_exc(e)


class Tthresholdmvba():

    def __init__(self, sid, pid, N, f, K, g1, g2, h, ePK, eSK, thpk, thpks, thsk, send, recv, mute=False, debug=None):
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
        self.h = h
        self.send = send
        self.scriptqueues = [Queue() for _ in range(K)]

    def run_bft(self):
        """Run the Dumbo protocol."""


        sid = self.sid
        pid = self.id
        round = 2
        adkr_old_recv = [Queue() for _ in range(round)]
        adkr_new_recv = [[Queue() for _ in range(self.N)] for _ in range(round)]
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
        for r in range(round):
            def adkr_old_send(k, o):
                self.send(k, (r, ('ADKR_OLD', o)))

            def adkr_new_send(k, o):
                self.send(k, (r, ('ADKR_NEW', o)))
            my_input = Queue()
            decide = [Queue() for _ in range(self.N)]

            rbc_threads = [None] * self.N
            for j in range(self.N):
                def make_rbc_send(j):  # this make will automatically deep copy the enclosed send func
                    def rbc_send(k, o):
                        """RBC send operation.
                        :param k: Node to send.
                        :param o: Value to send.
                        """
                        # print("node", pid, "is sending", o[0], "to node", k, "with the leader", j)
                        adkr_new_send(k, (j, o))

                    return rbc_send

                # Only leader gets input
                rbc_input = my_input.get if j == pid else None
                # rbc = gevent.spawn(strongprovablebroadcast, sid, pid, self.N, self.f, 0, self.C_o, self.thpk, self.thsk, j,
                #                    rbc_input, decide[j].put_nowait, adkr_new_recv[j].get, make_rbc_send(j), 0, logger
                #  =self.logger, predicate= lambda x: True)

                rbc = gevent.spawn(reliablebroadcast, sid + 'WRBC' + str(j), pid, self.N, self.f, j,
                                   rbc_input, adkr_new_recv[r][j].get, make_rbc_send(j))
                # cbc.get is a blocking function to get cbc output
                # cbc_outputs[j].put_nowait(cbc.get())
                rbc_threads[j] = rbc
                # gevent.sleep(0)
                # print(pid, "cbc start")

            my_input.put_nowait({1, 2, 3})
            s_time = time.time()
            gevent.joinall(rbc_threads)
            e_time = time.time()
            self.logger.info('run adkr taking %f sec' % (e_time - s_time))
            print('run adkr round taking %f sec' % (e_time - s_time))
        e_time = time.time()
        self.send(0, (-1, ('ADKR_COUNT', e_time - s_time)))
        if self.id == 0:
            co = 0
            co_n = 0
            print("=======================")
            self.logger.info('========================')
            while True:
                sender, ti = adkr_count_recv.get()
                co += ti
                co_n += 1
                print(sender, ":", ti)
                self.logger.info('node: %d\ttime: %f' % (sender, ti))
                if co_n == self.N:
                    print("")
                    print("avg:", co/self.N)
                    self.logger.info('avg:%f'%(co/self.N))
                    self.logger.info('========================')
                    break
        else:
            gevent.sleep(2)
        bc_recv_loop_thread.kill()
