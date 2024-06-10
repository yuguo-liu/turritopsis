from gevent import monkey; monkey.patch_all(thread=False)
import hashlib
import pickle

import copy
import time
import traceback
from datetime import datetime
import gevent
import numpy as np
from collections import namedtuple
from gevent import Greenlet
from gevent.event import Event
from enum import Enum
from collections import defaultdict
from gevent.queue import Queue
from utils.core.common_coin_bn import shared_coin
from dumbobft.core.baisedbinaryagreement import baisedbinaryagreement
#from dumbobft.core.haltingtwovalueagreement import haltingtwovalueagreement
#from mulebft.core.twovalueagreement import twovalueagreement
from dumbobft.core.consistentbroadcast import consistentbroadcast
from dumbobft.core.validators import cbc_validate
from honeybadgerbft.exceptions import UnknownTagError
from utils.core.reliablebroadcast import reliablebroadcast
from honeybadgerbft.core.reliablebroadcast import reliablebroadcast as r1
from utils.core.reproposableaba import pisaaragreement

from adkr.keyrefersh.core.thresholdcoin import thresholdcoin
from adkr.keyrefersh.core.thresholdcoin_bn import thresholdcoin_bn

class MessageTag(Enum):
    VABA_COIN = 'VABA_COIN'             # Queue()
    VABA_ABA_COIN = 'VABA_ABA_COIN'     # [Queue()] * Number_of_ABA_Iterations
    VABA_RBC = 'VABA_RBC'               # [Queue()] * N
    VABA_ABA = 'VABA_ABA'               # [Queue()] * Number_of_ABA_Iterations


MessageReceiverQueues = namedtuple(
    'MessageReceiverQueues', ('VABA_COIN', 'VABA_ABA_COIN', 'VABA_RBC', 'VABA_ABA'))



def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()


def tthresholdmvba(sid, pid, N, f, C, g, PKs, SK, input, decide, receive, send, localset_get, predicate, logger=None):
    """Multi-valued Byzantine consensus. It takes an input ``vi`` and will
    finally writes the decided value into ``decide`` channel.

    :param sid: session identifier
    :param pid: my id number
    :param N: the number of parties
    :param f: the number of byzantine parties
    :param PK: ``boldyreva.TBLSPublicKey`` with threshold f+1
    :param SK: ``boldyreva.TBLSPrivateKey`` with threshold f+1
    :param PK1: ``boldyreva.TBLSPublicKey`` with threshold n-f
    :param SK1: ``boldyreva.TBLSPrivateKey`` with threshold n-f
    :param list PK2s: an array of ``coincurve.PublicKey'', i.e., N public keys of ECDSA for all parties
    :param PublicKey SK2: ``coincurve.PrivateKey'', i.e., secret key of ECDSA
    :param input: ``input()`` is called to receive an input
    :param decide: ``decide()`` is eventually called
    :param receive: receive channel
    :param send: send channel
    :param predicate: ``predicate()`` represents the externally validated condition
    """

    # print("Starts to run validated agreement...")
    st = time.time()

    """ 
    """
    """ 
    Some instantiations
    """
    """ 
    """

    my_rbc_input = Queue(1)
    aba_inputs = defaultdict(lambda: Queue(1))

    aba_recvs = defaultdict(lambda: Queue())
    aba_coin_recvs = defaultdict(lambda: Queue())

    rbc_recvs = [Queue() for _ in range(N)]
    coin_recv = Queue()
    localset = set()
    rbc_threads = [None] * N
    rbc_outputs = [None for _ in range(N)]
    aba_outputs = defaultdict(lambda: Queue(1))

    is_rbc_delivered = [0] * N
    halt_signal = Event()
    recv_queues = MessageReceiverQueues(
        VABA_COIN=coin_recv,

        VABA_ABA_COIN=aba_coin_recvs,
        VABA_RBC=rbc_recvs,
        VABA_ABA=aba_recvs,
    )

    def recv_loop(recv_func, recv_queues):
        while True:
            sender, (tag, j, msg) = recv_func()
            # if pid ==1: print("recv2", (sender, (tag, j, msg[0])))

            if tag not in MessageTag.__members__:
                raise UnknownTagError('Unknown tag: {}! Must be one of {}.'.format(
                    tag, MessageTag.__members__.keys()))
            recv_queue = recv_queues._asdict()[tag]
            if tag not in {MessageTag.VABA_COIN.value}:
                recv_queue = recv_queue[j]
            try:
                recv_queue.put_nowait((sender, msg))
            except AttributeError as e:
                # print((sender, msg))
                traceback.print_exc(e)
            gevent.sleep(0)

    recv_loop_thred = Greenlet(recv_loop, receive, recv_queues)
    recv_loop_thred.start()
    halt_signal.clear()

    def get_local_set():

        # print(sid, pid, localset)
        while len(localset) < N:
            gevent.sleep(0)
            try:
                localset.add(localset_get())
                # print(localset)
            except Exception as e:
                # print(e)
                continue

    getlocal = gevent.spawn(get_local_set)
    """ 
    Setup the sub protocols Input Broadcast CBCs"""

    for j in range(N):

        def make_rbc_send(j): # this make will automatically deep copy the enclosed send func
            def rbc_send(k, o):
                """RBC send operation.
                :param k: Node to send.
                :param o: Value to send.
                """
                # print("node", pid, "is sending", o[0], "to node", k, "with the leader", j)
                send(k, ('VABA_RBC', j, o))
            return rbc_send

        # Only leader gets input
        rbc_input = my_rbc_input.get if j == pid else None
        # rbc = gevent.spawn(reliablebroadcast, sid + 'WRBC' + str(j), pid, N, f, j,
        #                    rbc_input, rbc_recvs[j].get, make_rbc_send(j))
        rbc = gevent.spawn(r1, sid + 'WRBC' + str(j), pid, N, f, j, rbc_input, rbc_recvs[j].get, make_rbc_send(j))
        # cbc.get is a blocking function to get cbc output
        #cbc_outputs[j].put_nowait(cbc.get())
        rbc_threads[j] = rbc
        # gevent.sleep(0)
        # print(pid, "cbc start")

    """ 
    Setup the sub protocols permutation coins"""

    def coin_bcast(o):
        """Common coin multicast operation.
        :param o: Value to multicast.
        """
        for i in C:
            send(i, ('VABA_COIN', 'leader_election', o))


    elect_coin = shared_coin(sid + 'ELECT', pid, N, f, 0, C, g,
                                   PKs, SK, coin_recv.get, coin_bcast, single_bit=False)



    # print(pid, "coin share start")
    # False means to get a coin of 256 bits instead of a single bit

    """ 
    """
    """ 
    Start to run consensus
    """
    """ 
    """

    """ 
    Run n CBC instance to consistently broadcast input values
    """

    # cbc_values = [Queue(1) for _ in range(N)]

    def wait_for_input():
        v = input()
        if logger != None:
            logger.info("VABA %s get input at %s" % (sid, datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]))
        # print("node %d gets VABA input %s" % (pid, v[0]))

        my_rbc_input.put_nowait(v)
        # print(v[0])
    gevent.spawn(wait_for_input)
    t_s = time.time()
    wait_rbc_signal = Event()
    wait_rbc_signal.clear()

    def wait_for_rbc_to_continue(leader):
        # Receive output from CBC broadcast for input values

        msg = rbc_threads[leader].get()

        while True:
            # print(localset, msg)
            if predicate(msg, localset):
                try:
                    if not rbc_outputs[leader]:
                        rbc_outputs[leader] = msg
                        is_rbc_delivered[leader] = 1
                        # print(sum(is_rbc_delivered))
                        if sum(is_rbc_delivered) >= N - f:
                            wait_rbc_signal.set()
                        break
                except:
                    pass

            else:
                pass
            gevent.sleep(0)
    rbc_out_threads = [gevent.spawn(wait_for_rbc_to_continue, node) for node in range(N)]

    wait_rbc_signal.wait()
    # print("Node %d finishes n-f RBC" % (pid))
    #print(is_cbc_delivered)
    #print(cbc_values)

    """
    Repeatedly run biased ABA instances until 1 is output 
    """

    r = 0
    a = None

    while True:
        propose_one = False
        seed = int.from_bytes(hash(sid + str(r)+str(2)), byteorder='big') % (2 ** 10 - 1)
        # if r < 5:
        # k = seed % N
        # print(pid, ": round", r, "leader index:", leader_index)
        """
        else:
            if ty == 's':
                coin = thresholdcoin(sid + 'PERMUTE', pid, N, f, l, C, g, seed, epks, esk, coin_recv.get, coin_bcast)
            elif ty == 'b':
                coin = thresholdcoin_bn(sid + 'PERMUTE', pid, N, f, l, C, g, seed, epks, esk, coin_recv.get, coin_bcast)
            leader_index = coin % N
            # seed = permutation_coin('permutation')  # Block to get a random seed to permute the list of nodes
        """
        t_c = time.time()
        seed = elect_coin(seed)

        # coin = thresholdcoin_bn(sid + 'PERMUTE', pid, N, f, 0, C, g, seed, PK, SK, coin_recv.get, coin_bcast)
        k = seed % N
        # permutation_coin = shared_coin(sid + 'PERMUTE', pid, N, f,
        #                                PK, SK, coin_bcast, coin_recv[r].get, single_bit=False)
        print(pid, ": round", r, "k:", k, time.time()-t_c)

        # print("coin has a seed:", seed)

        if is_rbc_delivered[k] == 1:
            aba_r_input = 1
        else:
            aba_r_input = 0
        def wait_for_repropose(r, k):
            while True:
                if is_rbc_delivered[k] == 1:
                    o = ('BVAL', r, (1, -1))
                    send(k, ('VABA_ABA', r, o))
                    break
                gevent.sleep(0)


        def aba_coin_bcast(o):
            """Common coin multicast operation.
            :param o: Value to multicast.
            """
            send(-1, ('VABA_ABA_COIN', r, o))


        coin = shared_coin(sid + 'COIN' + str(r), pid, N, f, 0, C, g,
                           PKs, SK,
                           aba_coin_recvs[r].get, aba_coin_bcast, single_bit=True)

        def make_aba_send(rnd): # this make will automatically deep copy the enclosed send func
            def aba_send(k, o):
                """CBC send operation.
                :param k: Node to send.
                :param o: Value to send.
                """
                # print("node", pid, "is sending", o, "to node", k, "with the leader", j)
                send(k, ('VABA_ABA', rnd, o))
            return aba_send

        # Only leader gets input
        aba = gevent.spawn(pisaaragreement, sid + 'ABA' + str(r), pid, N, f, coin,
                     aba_inputs[r].get, aba_outputs[r].put_nowait,
                     aba_recvs[r].get, make_aba_send(r))
        # aba.get is a blocking function to get aba output
        aba_inputs[r].put_nowait(aba_r_input)
        rpt = None
        if aba_r_input == 0:
            rpt = gevent.spawn(wait_for_repropose, r, k)

        aba_r = aba_outputs[r].get()
        print(pid, "Round", r, "ABA outputs", aba_r)
        if aba_r_input == 0:
            rpt.kill()

        # print("Round", r, "ABA outputs", aba_r)
        if aba_r == 1:
            # wait for wrbc_k deliver h_k
            while is_rbc_delivered[k] == 0:
                gevent.sleep(0)
            tk = rbc_outputs[k]


            """
            if tk != None:
                send(-1, ('VABA_COMMIT', -1, tk))
            #check wrbc_valus[k]
            else:
                while True:
                    v = commit_recv.get()
                    if hash(v) != wrbc_outputs[k]:
                        continue
                    else:
                        tk = v
                        break
            """
            decide(tk)
            break
        r += 1

    if logger != None:
        logger.info("VABA %s completes at round %d in %f second" % (sid, r, time.time()-st))
    print("node %d output in VABA %f" % (pid, time.time()-t_s))
    # decide(cbc_outputs[a].get()[0])
