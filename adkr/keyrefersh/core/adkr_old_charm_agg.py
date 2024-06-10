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
from charm.toolbox.ecgroup import ECGroup, G, ZR
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair

from adkr.keyrefersh.core.poly_misc_charm import interpolate_g_at_x
from adkr.keyrefersh.core.poly_misc_bn_charm import interpolate_g1_at_x, lagrange
from adkr.acss.core.acss_charm_agg import completesecretsharing
from speedmvba_dy.core.smvba_e_dy import speedmvba
from crypto.ecdsa.ecdsa import ecdsa_vrfy, ecdsa_sign
from operator import mul
from functools import reduce
from pickle import dumps, loads
import math

def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()


class BroadcastTag(Enum):
    ADKR_ACSS = 'ADKR_ACSS'
    ADKR_MVBA = 'ADKR_MVBA'
    ADKR_CONFIG = 'ADKR_CONFIG'


BroadcastReceiverQueues = namedtuple(
    'BroadcastReceiverQueues', ('ADKR_ACSS', 'ADKR_MVBA', 'ADKR_CONFIG'))


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
            if tag == BroadcastTag.ADKR_ACSS.value or tag == BroadcastTag.ADKR_MVBA.value:
                # print("put to ", j, "queue")
                recv_queue = recv_queue[j]

            recv_queue.put_nowait((sender, msg))

        except AttributeError as e:
            print("error", sender, (tag, j, msg))
            traceback.print_exc(e)


def ADKR_old_c(sid, pid, config_chain, l, f, round, g, type, sPK2s, sSK2, ePKs, eSK, thsk_o, thpk_o, thpks_o, output, send, recv, logger=None):
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
    if type == 's':
        group = ECGroup(714)
    elif type == 'b':
        group = PairingGroup('BN254')
    def hash2(m):
        try:
            m = m.encode()
        except:
            pass
        return group.hash(m, G2)
    C_o = config_chain[round]
    C_n = config_chain[round+1]
    N_o = len(C_o)
    N_n = len(C_n)
    l_o = l
    f_o = f
    l_n = l
    f_n = f
    _per_round_recv = {}  # Buffer of incoming messages
    _per_round_config = {}

    def verify_knowledge_of_discrete_log(pk, g, Y, c, proof):
        T, z, e_u, w = proof
        e = group.hash(dumps([pk, group.serialize(g), Y, c, T]))
        # be_secure is default true and adds a randomizing factor to the ciphertext as a failsafe.
        # we need it turned off so that the calculations will be correct
        c_e = pow(c, int(e), pk.nsquare)
        return group.deserialize(T) == (g ** z) * (group.deserialize(Y) ** (-e)) and \
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
    def run_round(secret_r, send):
        """Run one protocol round.
        :param secret_r: round secret to share
        :param send:
        :param recv:
        """

        # Unique sid for each round
        print("old", C_o)
        print("new", C_n)
        my_acss_input = Queue(1)

        acss_value_outputs = defaultdict(lambda: defaultdict())
        acss_output_index = Queue()
        acss_output_count = set()
        vaba_input = Queue(1)
        vaba_output = Queue(1)
        ba_signal = Event()

        # print(pid, r, 'tx_to_send:')
        acss_threads = [None] * N_o
        # print("g1", print(group.serialize(g)))
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
            acss_thread = gevent.spawn(completesecretsharing, sid+'ACSS'+str(C_o[j]), pid, round,
                                     N_o, f_o, l_o, C_o, N_n, f_n, l_n, C_n, g, type, C_o[j], ePKs, eSK, acss_input,
                                     receive=acss_recvs[j].get, send=acss_send, logger=logger)

            def wait_for_acss_output():
                comms, encryptions, proofs = acss_thread.get()
                # print(script)
                try:
                    # acss_proofs[sid+'PB'+str(r)+str(j)] = proof
                    acss_value_outputs[j][0] = comms
                    acss_value_outputs[j][1] = encryptions
                    acss_value_outputs[j][2] = proofs
                    acss_output_index.put_nowait(j)
                    acss_output_count.add(j)
                    if len(acss_output_count) == f_o + 1:
                        ba_signal.set()
                except TypeError as e:
                    print(e)
                    #return False

            gevent.spawn(wait_for_acss_output)

            return acss_thread

        # N instances of PB
        for j in range(N_o):
            # print("start to set up ACSS %d" % j)
            acss_threads[j] = _setup_acss(j)


        ba_signal.wait()
        ba_signal.clear()

        def ba_round(r, t, ls):

            def make_vaba_send():  # this make will automatically deep copy the enclosed send func
                def vaba_send(k, o):
                    """MVBA send operation.
                    :param k: Node to send.
                    :param o: Value to send.
                    """
                    send(k, ('ADKR_MVBA', r, o))

                return vaba_send

            def make_vaba_predicate():
                def vaba_predicate(m, local_set):
                    if len(m) == f_o + 1:
                        if m.issubset(local_set):
                            # print("true")
                            return True
                        else:
                            print(m, local_set)
                            gevent.sleep(1)
                            # print("false")
                            return False
                    else:
                        return False

                return vaba_predicate
            vaba_thread = gevent.spawn(speedmvba, sid + 'AKDR-MVBA'+str(r), pid, N_o, f_o, l_o, C_o, sPK2s, sSK2, thpks_o, thsk_o, g, type,
                                vaba_input.get, vaba_output.put_nowait, mvba_recvs[r].get, make_vaba_send(), acss_output_index.get_nowait, ls,
                                predicate=make_vaba_predicate(), logger=logger)

            vaba_thread.start()
            # print("start mvba")

            # print("acss output index", t)
            vaba_input.put_nowait(t)
            out, localset = vaba_output.get()
            # print(r, "vaba_output:", out)
            for i in out:
                if C_o[i] == pid:
                    continue
                else:
                    if not predicate(C_o[i], acss_value_outputs[i][0], acss_value_outputs[i][1], acss_value_outputs[i][2]):
                        print("wrong one in out")
                        return 'w', C_o[i], localset
            return 'r', out, 0
        r = 0
        ls = None
        while True:
            t = set(list(acss_output_count)[:f_o + 1])
            # print(r, ":the set is", t)
            result, m, ls = ba_round(r, t, ls)
            if result == 'w':
                # print("remove", m, "ls", ls)
                if m in acss_output_count:
                    acss_output_count.remove(m)
                r += 1
            else:
                out = m
                break



        # if logger != None:
        #     logger.info('vaba_output: %s', out)
        commit = {}
        share_e = {}
        pk_shares = []
        pk_shares_s = []
        for i in range(N_n):
            if type == 's':
                commit[i] = group.init(G)
            elif type == 'b':
                commit[i] = group.init(G1)
            encn = ePKs[C_n[i]].encrypt(int(0))
            share_e[i] = encn.ciphertext(be_secure=False)
            for j in out:
                share_e[i] = encn._raw_add(acss_value_outputs[j][1][i], share_e[i])
                commit[i] = commit[i] * group.deserialize(acss_value_outputs[j][0][i])
            pk_shares.append([C_n[i] + 1, commit[i]])
            pk_shares_s.append([C_n[i] + 1, group.serialize(commit[i])])
            # print(pid, "append", C_n[i] + 1, commit[i])
        if type == 's':
            thpk = interpolate_g_at_x(pk_shares[:f_o+1], 0, group.init(G))

            digest = hash(str(thpk) + str(C_n))
            script = (pk_shares_s, share_e, group.serialize(thpk), C_n)
            # assert thpk == g ** (f_o+1)
            sigma = ecdsa_sign(sSK2, digest)
            for i in C_o:
                send(i, ('ADKR_CONFIG', 0, (script, sigma)))
                # print(pid, "send AKDR CONFIG")

        elif type == 'b':

            thpk = interpolate_g1_at_x(pk_shares[:f_o + 1], 0, group.init(G1))
            # assert thpk == g ** (f_o + 1)
            digest = hash2(str(thpk))
            digest2 = hash2(str(thpk) + str(C_n))
            script = (pk_shares_s, share_e, group.serialize(thpk), C_n)
            sigma = digest ** thsk_o
            sigma2 = digest2 ** thsk_o
            for i in C_o:
                send(i, ('ADKR_CONFIG', 0, (script, (group.serialize(sigma), group.serialize(sigma2)))))
        # print(pid, "get pkshares:", pk_shares)






    #self._recv_thread = gevent.spawn(_recv_loop)
    acss_recvs = [Queue() for _ in range(N_o)]
    mvba_recvs = defaultdict(lambda: Queue())
    config_recv = Queue()

    recv_queues = BroadcastReceiverQueues(
        ADKR_ACSS=acss_recvs,
        ADKR_MVBA=mvba_recvs,
        ADKR_CONFIG=config_recv
    )
    bc_recv_loop_thread = Greenlet(broadcast_receiver_loop, recv, recv_queues, logger)
    bc_recv_loop_thread.start()


    s_time = time.time()
    if logger != None:
        logger.info('Node %d starts to run at time:' % pid + str(s_time))

    #gevent.sleep(0)

    start = time.time()

    def _make_send():
        def _send(j, o):
            send(j, o)
        return _send

    send_r = _make_send()

    secret_r = 1
    # secret_r = ZR.random()
    def wait_for_config():
        pk_digest_count = defaultdict()
        pk_digest = defaultdict(lambda: set())
        pk_digest_bn = defaultdict(lambda: list())
        pk_digest_bn2 = defaultdict(lambda: list())
        while True:
            try:

                sender, ((pk_shares_s, share_e, thpk_s, C_n), sigma) = config_recv.get(0.000001)
                thpk = group.deserialize(thpk_s)
                pk_shares = []
                for itme in pk_shares_s:
                    pk_shares.append([itme[0], group.deserialize(itme[1])])
                if type == 's':
                    digest = hash(str(thpk) + str(C_n))
                    if ecdsa_vrfy(sPK2s[sender], digest, sigma):

                        pk_digest[digest].add((sender, sigma))
                        if len(pk_digest[digest]) == f_o + 1:
                            # print(pid, "RECEIVE f+1 signatures and put")
                            output(((pk_shares_s, share_e, thpk_s, C_n), pk_digest[digest]))
                            return
                    # print(pid, "recv from", sender, thpk)
                    else:
                        print("wrong sig!")
                        continue
                elif type == 'b':
                    sigma1, sigma2 = sigma
                    sigma1_d = group.deserialize(sigma1)
                    sigma2_d = group.deserialize(sigma2)
                    digest1 = hash2(str(thpk))
                    digest2 = hash2(str(thpk) + str(C_n))
                    # print(thpk)
                    if pair(g, sigma1_d) == pair(thpks_o[C_o.index(sender)][1], digest1) and \
                        pair(g, sigma2_d) == pair(thpks_o[C_o.index(sender)][1], digest2):
                        # print(pid, 'verify', sender, 'right')
                        pk_digest_bn[digest1].append([sender+1, sigma1_d])
                        pk_digest_bn2[digest2].append([sender+1, sigma2_d])
                        if len(pk_digest_bn[digest1]) == f_o + 1:
                            Sigma = interpolate_g1_at_x(pk_digest_bn[digest1][:f_o + 1], 0, group.init(G2))
                            Sigma2 = interpolate_g1_at_x(pk_digest_bn2[digest2][:f_o + 1], 0, group.init(G2))
                            # print(pid, 'Sigma', Sigma)

                            # assert pair(g, Sigma) == pair(thpk_o, digest1)
                            # assert pair(g, Sigma2) == pair(thpk_o, digest2)
                            # print("here", g, Sigma, thpk_o, digest)
                            output(((thpk_s, Sigma), pk_shares_s, share_e, C_n, Sigma2, digest2))
                            return
            except Exception as e:
                traceback.print_exc(e)
                continue

    run_round(secret_r, send_r)
    t = gevent.spawn(wait_for_config)
    t.join()

    end = time.time()

    if logger != None:
        logger.info('ADKR-OLD Delay at Node %d: ' % pid + str(end - start))