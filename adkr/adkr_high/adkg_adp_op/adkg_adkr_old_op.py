import copy

from gevent import monkey; monkey.patch_all(thread=False)

import json
import logging
import os
import traceback, time
import gevent
import numpy as np
import hashlib
import pickle
from collections import namedtuple
from enum import Enum
from gevent import Greenlet
from gevent.queue import Queue
from collections import defaultdict
from gevent.event import Event
from honeybadgerbft.exceptions import UnknownTagError
from utils.core.betterpairing import G1, ZR
from utils.core.serializer import serialize, deserialize
from adkr.keyrefersh.core.poly_misc_bn import interpolate_g1_at_x, lagrange
from adkr.adkr_high.adkg_adp_op.acss_rbc_op import completesecretsharing
from adkr.adkr_high.adkg_adp_op.smvba_dy_inter import speedmvba
from utils.core.common_coin_bn import shared_coin
from utils.core.tthresholdmvba import tthresholdmvba

from utils.core.bls_bn import sign, verify_share, verify_signature, hash_message, combine_shares
from operator import mul
from functools import reduce
from pickle import dumps, loads
import math
from utils.core.serializer import serialize_G2,deseralize_G2
def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()


class BroadcastTag(Enum):
    ADKR_ACSS = 'ADKR_ACSS'
    ADKR_MVBA = 'ADKR_MVBA'
    ADKR_CONFIG = 'ADKR_CONFIG'
    ADKR_PERM = 'ADKR_PERM'


BroadcastReceiverQueues = namedtuple(
    'BroadcastReceiverQueues', ('ADKR_ACSS', 'ADKR_MVBA', 'ADKR_CONFIG', 'ADKR_PERM'))


def broadcast_receiver_loop(recv_func, recv_queues, logger):
    while True:
        #gevent.sleep(0)
        sender, (tag, j, msg) = recv_func()
        # print("recv", (sender, tag))
        # logger.info('recv %s %s' % (sender, tag))
        if tag not in BroadcastTag.__members__:
            # TODO Post python 3 port: Add exception chaining.
            # See https://www.python.org/dev/peps/pep-3134/
            raise UnknownTagError('Unknown tag: {}! Must be one of {}.'.format(
                tag, BroadcastTag.__members__.keys()))
        recv_queue = recv_queues._asdict()[tag]


        try:
            if tag == BroadcastTag.ADKR_ACSS.value:
                # print("put to ", j, "queue")
                recv_queue = recv_queue[j]

            recv_queue.put_nowait((sender, msg))

        except AttributeError as e:
            print("error", sender, (tag, j, msg))
            traceback.print_exc(e)


def ADKR_old_c(sid, pid, C_o, C_n, f, K, g, PK1, PK1s, SK1, ePKs, eSK, send, send2, recv, logger=None):
    """AKDR object used to run the protocol.

    :param str sid: The base name of the common coin that will be used to
        derive a nonce to uniquely identify the coin.
    :param int pid: Node id.
    :param int B: Batch size of transactions.
    :param int N: Number of nodes in the network.
    :param int f: Number of faulty nodes that can be tolerated.
    :param TBLSPublicKey sPK: Public key of the (f, N) threshold signature
        (:math:`\mathsf{TSIG}`) scheme.
    :param TBLSPrivateKey sSK: Signing key of the (f, N) threshold signature
        (:math:`\mathsf{TSIG}`) scheme.
    :param TBLSPublicKey sPK1: Public key of the (N-f, N) threshold signature
        (:math:`\mathsf{TSIG}`) scheme.
    :param TBLSPrivateKey sSK1: Signing key of the (N-f, N) threshold signature
        (:math:`\mathsf{TSIG}`) scheme.
    :param list sPK2s: Public key(s) of ECDSA signature for all N parties.
    :param PrivateKey sSK2: Signing key of ECDSA signature.
    :param str ePK: Public key of the threshold encryption
        (:math:`\mathsf{TPKE}`) scheme.
    :param str eSK: Signing key of the threshold encryption
        (:math:`\mathsf{TPKE}`) scheme.
    :param send:
    :param recv:
    :param K: a test parameter to specify break out after K rounds
    """


    N_o = len(C_o)
    N_n = len(C_n)

    f_o = f

    f_n = f
    _per_round_recv = {}  # Buffer of incoming messages
    _per_round_config = {}

    def verify_knowledge_of_discrete_log(pk, g, Y, c, proof):
        T, z, e_u, w = proof
        e = ZR.hash(dumps([pk, serialize(g), Y, c, T]))
        # be_secure is default true and adds a randomizing factor to the ciphertext as a failsafe.
        # we need it turned off so that the calculations will be correct
        c_e = pow(c, int(e), pk.nsquare)
        return deserialize(T) == (g ** z) * (deserialize(Y) ** (-e)) and \
               (e_u.ciphertext(be_secure=False) * c_e) % pk.nsquare == pk.encrypt(z, r_value=w).ciphertext(
            be_secure=False)



    def predicate(dealer, comms, encryptions, proofs):
        try:
            for i in range(N_n):
                # if dealer == 2: print(PKs[C_n[i]], g, comms[i], encryptions[i], proofs[i])
                if not verify_knowledge_of_discrete_log(ePKs[C_n[i]], g, comms[i], encryptions[i], proofs[i]):
                    print(pid, "verify failed", C_n[i], "for dealer", dealer)
                    return False
                # pass
            return True
        except Exception as e:
            print("Failed to verify acss script:", e)
    # print(pid, thpk_o)



    # Unique sid for each round
    # print("old", C_o)
    # print("new", C_n)
    my_acss_input = Queue(1)

    acss_value_outputs = defaultdict(lambda: defaultdict())
    acss_outputs = [Queue() for _ in range(N_o)]
    acss_store_list = [None for _ in range(N_o)]
    acss_lock_list = [None for _ in range(N_o)]
    acss_output_index = Queue()
    acss_output_count = set()
    t = [None for _ in range(N_o)]
    count_num = Queue()
    vaba_input = Queue(1)
    vaba_output = Queue(1)
    ba_signal = Event()
    acss_index = list()
    # print(pid, r, 'tx_to_send:')
    acss_threads = [None] * N_o
    # self._recv_thread = gevent.spawn(_recv_loop)
    acss_recvs = [Queue() for _ in range(N_o)]
    mvba_recvs = Queue()
    config_recv = Queue()
    coin_recv = Queue()
    secret_r = 1
    recv_queues = BroadcastReceiverQueues(
        ADKR_ACSS=acss_recvs,
        ADKR_MVBA=mvba_recvs,
        ADKR_CONFIG=config_recv,
        ADKR_PERM = coin_recv
    )
    bc_recv_loop_thread = Greenlet(broadcast_receiver_loop, recv, recv_queues, logger)
    bc_recv_loop_thread.start()
    # print("g1", print(group.serialize(g)))
    s_time = time.time()
    def _setup_acss(j):
        """Setup the ACSS.
        :param int j: Node index for ACSS dealer.
        """

        def acss_send(k, o):
            """Reliable send operation.
            :param k: Node to send.
            :param o: Value to send.
            """
            send(k, ('ADKR_ACSS', j, o))

        # Only leader gets input
        acss_input = my_acss_input.get if C_o[j] == pid else None
        if C_o[j] == pid:
            my_acss_input.put_nowait(secret_r)

        acss_thread = gevent.spawn(completesecretsharing, sid+'ACSS'+str(C_o[j]), pid,
                                 N_o, f_o, C_o, N_n, 2*f_n, C_n, g, C_o[j], ePKs, eSK, PK1, SK1,
                                   acss_input,  acss_outputs[j].put_nowait,
                                 receive=acss_recvs[j].get, send=acss_send, logger=None)
        # print(pid, "start", j)
        def wait_for_acss_output():

            # print(script)
            script = acss_thread.get()
            if script == -1:
                print("get wrong acss script", j)
                return
            comms, encryptions, proofs = script
            # print(script)
            try:
                # acss_proofs[sid+'PB'+str(r)+str(j)] = proof
                acss_value_outputs[j][0] = comms
                acss_value_outputs[j][1] = encryptions
                acss_value_outputs[j][2] = proofs
                acss_output_index.put_nowait(j)
                acss_output_count.add(j)
                # print("add", j, acss_output_count)
                if len(acss_output_count) == f_o + 1:
                    print(pid, "here")
                    ba_signal.set()

            except TypeError as e:
                print(e)
                # return False

                    #return False

        gevent.spawn(wait_for_acss_output)

        return acss_thread

    start = time.time()
    # N instances of PB
    for j in range(N_o):
        # print(pid, "start to set up ACSS %d" % j)
        _setup_acss(j)






    def make_vaba_send():  # this make will automatically deep copy the enclosed send func
        def vaba_send(k, o):
            """MVBA send operation.
            :param k: Node to send.
            :param o: Value to send.
            """
            # print(pid, "send", o[0], "k", o)
            send(k, ('ADKR_MVBA', 0, o))

        return vaba_send

    def make_vaba_predicate():
        def vaba_predicate(m, local_set):
            # print("??????")
            # print(m)
            if len(m) == f_o + 1:
                if m.issubset(local_set):
                    # print("true")
                    return True
            else:
                # print("false")
                return False

        return vaba_predicate

    ba_signal.wait()
    ba_signal.clear()
    t = set(list(acss_output_count)[:f_o + 1])
    print(t)
    logger.info('f+1 acss taking %f' %(time.time()-s_time))
    print(time.time()-s_time)
    vaba_thread = gevent.spawn(speedmvba, sid + 'AKDR-MVBA', pid, N_o, f_o, 0, C_o, PK1, PK1s, SK1, g,
                               input=vaba_input.get, decide=vaba_output.put_nowait, receive=mvba_recvs.get, send=make_vaba_send(),
                               localset_get=acss_output_index.get_nowait,
                               predicate=make_vaba_predicate(), logger=logger)

    vaba_thread.start()

    vaba_input.put_nowait(t)
    print("start mvba")
    st = time.time()

    # t = acss_output_count


    out = vaba_output.get()
    print("out", out)
    # if logger:
    logger.info('mvba taking: %f sec' % (time.time()-st))
    for i in out:
        if i == pid:
            continue
        else:
            if not predicate(C_o[i], acss_value_outputs[i][0], acss_value_outputs[i][1], acss_value_outputs[i][2]):
                print("wrong one in out")
                out.remove(i)
    commit = {}
    share_e = {}
    pk_shares = []
    pk_shares_s = []
    for i in range(N_n):
        commit[i] = G1.identity()
        # encn = ePKs[C_n[i]].encrypt(int(0))
        # share_e[i] = encn.ciphertext(be_secure=False)
        share_e[i] = acss_value_outputs[0][1][i]
        for j in out:
            # share_e[i] = encn._raw_add(acss_value_outputs[j][1][i], share_e[i])
            if j > 0:
                share_e[i] = share_e[i]+acss_value_outputs[j][1][i]
            commit[i] = commit[i] * deserialize(acss_value_outputs[j][0][i])
        pk_shares.append([C_n[i] + 1, commit[i]])
        pk_shares_s.append([C_n[i] + 1, serialize(commit[i])])
        # print(pid, "append", C_n[i] + 1, commit[i])

    thpk = interpolate_g1_at_x(pk_shares[:2*f_n + 1], 0, G1.identity())
    assert thpk == g ** (f+1)

    script = (pk_shares_s, share_e, serialize(thpk), C_n)
    # print(thpk)
    def rc_bcast(o):
        """Common coin multicast operation.
        :param o: Value to multicast.
        """
        for i in C_n:
            send2(i, ('ADKR_NEW_RC', o))

    rc_bcast(script)

    end = time.time()
    print(end-start)

    if logger != None:
        logger.info('ADKR-OLD Delay at Node %d: ' % pid + str(end - start))

    return dumps(script)