from gevent import monkey; monkey.patch_all(thread=False)

import time
import traceback
from datetime import datetime

import gevent
from collections import namedtuple
from enum import Enum
from speedmvba_dy.core.smvba_thcoin_dy import speedmvba
from gevent.queue import Queue
from honeybadgerbft.exceptions import UnknownTagError
from gevent.event import Event

from collections import defaultdict

class MessageTag(Enum):
    VACS_VAL = 'VACS_VAL'            # Queue()
    VACS_VABA = 'VACS_VABA'          # Queue()


MessageReceiverQueues = namedtuple(
    'MessageReceiverQueues', ('VACS_VAL', 'VACS_VABA'))


def vacs_msg_receiving_loop(recv_func, recv_queues):
    while True:
        #gevent.sleep(0)
        sender, (tag, msg) = recv_func()
        # print(sender, (tag, msg))
        if tag not in MessageTag.__members__:
            # TODO Post python 3 port: Add exception chaining.
            # See https://www.python.org/dev/peps/pep-3134/
            raise UnknownTagError('Unknown tag: {}! Must be one of {}.'.format(
                tag, MessageTag.__members__.keys()))
        recv_queue = recv_queues._asdict()[tag]
        try:
            recv_queue.put_nowait((sender, msg))
        except AttributeError as e:
            # print((sender, msg))
            traceback.print_exc(e)


def speedmvbacommonsubset(sid, pid, C, r, reconfig, N, f, l, last_pb_proof, PK2s, SK2, epks, esk, g, ty, input, decide, left_decide, receive, send, predicate=lambda i, v, t: True, logger=None):
    """Validated vector consensus. It takes an input ``vi`` and will
    finally writes the decided value (i.e., a vector of different nodes' vi) into ``decide`` channel.
    Each vi is validated by a predicate function predicate(i, vi)

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
    :param predicate: ``predicate(i, v)`` represents the externally validated condition where i represent proposer's pid
    """

    #print("Starts to run validated common subset...")

    #assert PK.k == f + 1
    #assert PK.l == N
    #assert PK1.k == N - f
    #assert PK1.l == N

    """ 
    """
    """ 
    Some instantiations
    """
    """ 
    """

    valueSenders = set()  # Peers that have sent us valid VAL messages

    vaba_input = Queue(1)
    vaba_recv = Queue()
    vaba_output = Queue(1)

    value_recv = Queue()
    proof_signal = Event()
    left_pb = defaultdict()
    recv_queues = MessageReceiverQueues(
        VACS_VAL=value_recv,
        VACS_VABA=vaba_recv,
    )
    gevent.spawn(vacs_msg_receiving_loop, receive, recv_queues)

    def make_vaba_send():  # this make will automatically deep copy the enclosed send func
        def vaba_send(k, o):
            """VACS-VABA send operation.
            :param k: Node to send.
            :param o: Value to send.
            """
            send(k, ('VACS_VABA', o))

        return vaba_send

    def make_vaba_predicate():
        def vaba_predicate(m):
            counter1 = 0
            counter2 = 0
            if type(m) is tuple:
                if len(m) == 2 * N:
                    for i in range(N):
                        if m[i] is not None and predicate(i, m[i], 1):
                            counter1 += 1
                    for i in range(N, 2*N):
                        if m[i] is not None and predicate(i-N, m[i], 0):
                            counter2 += 1
            if counter1 >= N - f - l:
                # print("mvba predicate True")
                # print(counter2)
                return True
            else:
                logger.info('mvba predicate false')
                print("mvba predicate false")
                return False

        return vaba_predicate


    vaba = gevent.spawn(speedmvba, sid + 'VACS-VABA', pid, N, f, l, C, PK2s, SK2, epks, esk, g, ty,
                        vaba_input.get, vaba_output.put_nowait, vaba_recv.get, make_vaba_send(), make_vaba_predicate(), logger)

    """ 
    """
    """ 
    Execution
    """
    """ 
    """

    def wait_for_input():
        v = input()
        # if logger != None:
        #     logger.info("VACS gets input")
        # print("node %d gets VACS input" % pid)
        # assert predicate(pid, v)
        for i in C:
            send(i, ('VACS_VAL', v))


    gevent.spawn(wait_for_input)

    values = [None]* N * 2
    values_t = [None]* N * 2
    proof_signal.clear()
    def wait_pb_proofs():
        nonlocal values, values_t
        while True:
            j, vj = value_recv.get()
            # print("recvj", j)
            try:
                assert predicate(C.index(j), vj, 1)
                valueSenders.add(j)
                values_t[C.index(j)] = vj
                if proof_signal.is_set():
                    values_t[C.index(j)] = vj
                if len(valueSenders) >= N - f - l:
                    proof_signal.set()
                    values = values_t.copy()
            except:
                traceback.print_exc()

    w_p_t = gevent.spawn(wait_pb_proofs)
    # print(pid, "values:", tuple(values))
    proof_signal.wait()
    if r % reconfig != 1 or r == 1:
        for i in last_pb_proof.keys():
            values[N + i] = last_pb_proof[i]
    vaba_input.put_nowait(tuple(values))
    vector = list(vaba_output.get())
    # print(vector)
    decide(vector)

    c0 = -1
    t0 = list()
    for items in vector:
        c0 = c0 + 1
        if items is None:
            continue
        t0.append(c0)

    c = -1
    t = list()
    for items in values_t:
        c = c + 1
        if items is None:
            continue
        t.append(c)

    # print("vaba vector", t0)
    # print("values vector", t)
    for item in t:
        if item not in t0:
            left_pb[item] = values_t[item]


    #if logger != None:
    #    logger.info("VACS completes")
    #print("node %d output in VACS" % pid)

    vaba.kill()
    # gevent.sleep(1)
    value_recv = None
    vaba_recv = None
    w_p_t.kill()
    # print("left these pb with proofs, can be add to next round", left_pb.keys())
    left_decide(left_pb)