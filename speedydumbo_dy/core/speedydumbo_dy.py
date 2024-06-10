import copy
import gc

from gevent import monkey; monkey.patch_all(thread=False)
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
from crypto.ecdsa.ecdsa import ecdsa_vrfy, ecdsa_sign
from adkr.keyrefersh.core.poly_misc_charm import interpolate_g_at_x
from speedydumbo_dy.core.speedydumbocommonsubset import speedydumbocommonsubset
from speedydumbo_dy.core.provablebroadcast import provablebroadcast
from speedydumbo_dy.core.validators import pb_validate
from dumbobft.core.speedmvbacommonsubset_dy import speedmvbacommonsubset
from adkr.keyrefersh.core.adkr_old_charm_agg import ADKR_old_c
from pickle import dumps, loads
from honeybadgerbft.exceptions import UnknownTagError
import hashlib
import dill
import statistics
# from charm.toolbox.ecgroup import ECGroup
from charm.toolbox.ecgroup import ECGroup, G


group = ECGroup(714)
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
    ACS_PRBC = 'ACS_PRBC'
    ACS_VACS = 'ACS_VACS'
    TPKE = 'TPKE'


BroadcastReceiverQueues = namedtuple(
    'BroadcastReceiverQueues', ('ACS_PRBC', 'ACS_VACS', 'TPKE', 'ADKR_NEW', 'ADKR_OLD'))


def broadcast_receiver_loop(recv_func, recv_queues, C, logger):
    while True:
        #gevent.sleep(0)
        sender, (tag, j, msg) = recv_func()
        # if tag == 'AKDR_OLD':
            # print('recv_sd', sender, tag)
        # logger.info('recv %d %s' % (sender, tag))
        if tag not in BroadcastTag.__members__:
            # TODO Post python 3 port: Add exception chaining.
            # See https://www.python.org/dev/peps/pep-3134/
            raise UnknownTagError('Unknown tag: {}! Must be one of {}.'.format(
                tag, BroadcastTag.__members__.keys()))
        recv_queue = recv_queues._asdict()[tag]

        if tag == BroadcastTag.ACS_PRBC.value:
            # print("putinto ", C.index(j))
            recv_queue = recv_queue[C.index(j)]
        try:
            recv_queue.put_nowait((sender, msg))
        except AttributeError as e:
            print("error", sender, (tag, j, msg))
            traceback.print_exc(e)


class SpeedyDumbo():
    """Dumbo object used to run the protocol.

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

    def __init__(self, sid, pid, B, B_m, l, f, C_g, N_all, reconfig, l_list, g1, ec, sPK2s, sSK2, ePK, eSK, thpk, thpks, thsk, send,recv, K=3, mute=False, debug=None):
        self.sid = sid
        self.id = pid
        self.B = B
        self.B_m = B_m
        self.C_g = C_g
        self.C_n = C_g
        self.C_o = []
        self.N_n = len(self.C_n)
        self.l_n = l
        self.f_n = f
        self.N_o = 0
        self.f_o = f
        self.N_g = len(C_g)
        self.f_g = f
        self.reconfig = reconfig
        self.ec = ec
        self.sPK2s = sPK2s
        self.sSK2 = sSK2
        self.ePKS = ePK
        self.eSK = eSK
        self.thepks = 0
        self.thepk = 0
        self.thesk = 0
        self._send = send
        self._recv = recv
        self.logger = set_consensus_log(pid)

        self.proofchain = defaultdict(lambda: tuple())
        self.configchain = defaultdict(lambda: list())
        self.salvagset = defaultdict(lambda:defaultdict())
        self.pb_value_outputs = defaultdict(lambda :[Queue(1) for _ in range(self.N_g)])
        self.pb_proof_output = defaultdict(lambda :Queue(1))
        self.last_pb_proof = defaultdict()
        self.round = 0  # Current block number
        self.start_round = 0
        self.transaction_buffer = Queue()
        self.mem_buffer = Queue()
        self._per_round_recv = {}  # Buffer of incoming messages
        self.config_recv = Queue()
        self.halt_recv = Queue()
        self.data_recv = Queue()
        self.data = defaultdict(lambda :list())
        self.K = K

        self.s_time = 0
        self.e_time = 0
        self.txcnt = 0

        self.mute = mute
        self.debug = debug
        self.leave_signal = Event()
        self.l_list = l_list
        self.g1 = g1
        self.N_all  = N_all
        if self.id in C_g:
            self.thesk = thsk
            self.thepk = thpk
            self.thepks = thpks
        self.thpk_g = thpk
        print(self.debug)
    def submit_mem(self, o, p):
        self.mem_buffer.put_nowait((o, p))

    def submit_tx(self, tx):
        """Appends the given transaction to the transaction buffer.
        :param tx: Transaction to append to the buffer.
        """
        #print('backlog_tx', self.id, tx)
        #if self.logger != None:
        #    self.logger.info('Backlogged tx at Node %d:' % self.id + str(tx))
        # Insert transactions to the end of TX buffer
        self.transaction_buffer.put_nowait(tx)

    def run_bft(self):
        """Run the Dumbo protocol."""


        def _recv_loop():
            """Receive messages."""
            count = 0
            #print("start recv loop...")
            while True:
                #gevent.sleep(0)
                try:
                    (sender, (r, msg)) = self._recv()
                    # print(self.id, "recv_sdumobo", r, msg[0])
                    # self.logger.info('recv1 %s' % (msg[0]))
                    # Maintain an *unbounded* recv queue for each epoch
                    if r == -2:
                        # its a new config msg
                        self.config_recv.put_nowait((sender, msg))
                    elif r == -3:
                        self.halt_recv.put_nowait((sender, msg))
                    elif r == -4:
                        # print("reciv!!!!!!!!!")
                        self.data_recv.put_nowait((sender, msg))
                    elif r not in self._per_round_recv:
                        self._per_round_recv[r] = Queue()
                    # Buffer this message
                    self._per_round_recv[r].put_nowait((sender, msg))
                    count += 1
                except Exception as e:
                    # print(e)
                    continue
        def wait_for_config():

            def verify_sig(Sigma, script, C_o):
                # print(len(Sigma))
                print(C_o)
                # print(int((len(C_o) - 1) / 3)+1)
                if len(Sigma) != self.f_o + 1:
                    print("sigma set error")
                    return False

                (pk_shares, share_e, thpk, C_n) = script
                digest = hash(str(thpk) + str(C_n))
                for item in Sigma:
                    # print(item)
                    (id, sig) = item
                    if id not in C_o:
                        print("config member error")
                        return False
                    if not ecdsa_vrfy(self.sPK2s[id], digest, sig):
                        print("sig verify error")
                        return False
                return True

            self.configchain[0] = self.C_g
            self.C_o = self.C_g
            self.N_o = len(self.C_o)
            self.l_o = self.l_n
            self.f_o = self.f_g
            # print(self.id, self.C_g, self.f_o)
            if self.id not in self.C_g:

                while True:
                    try:
                        sender, (_, round, proof_chain_r) = self.config_recv.get(0.000001)
                        p_stime = time.time()
                        proof_chain = dill.loads(proof_chain_r)
                        # print(self.id, "recv a config msg from", sender)
                        for c in proof_chain.keys():
                            # proof_chain[c] contains script for config[c+1], signed by config[c]
                            if c == self.reconfig:
                                self.configchain[0] = self.C_g
                            (script, Sigma) = proof_chain[c]
                            self.configchain[c] = script[3]
                            (pk_shares_s, share_e, thpk_s, C_n) = script
                            thpk = group.deserialize(thpk_s)
                            assert thpk == self.g1 ** (self.f_g+1)
                            pk_shares = []
                            for itme in pk_shares_s:
                                pk_shares.append([itme[0], group.deserialize(itme[1])])
                            # print("c:", c, "member:", self.configchain[c - self.reconfig])
                            if not verify_sig(Sigma, (pk_shares, share_e, thpk, C_n),
                                              self.configchain[c - self.reconfig]):
                                print("verify_sig error")
                                break

                            self.proofchain[c] = proof_chain[c]
                            # self.configchain[c+self.reconfig] = C_n
                            if c == round:
                                self.C_o = C_n
                                self.configchain[c + 1] = C_n
                                self.N_o = len(self.C_o)
                                self.l_o = self.l_n
                                self.f_o = self.f_g
                        print(self.id, "config verify passed!")
                        share_m = self.eSK.raw_decrypt(share_e[self.C_o.index(self.id)])
                        self.thepks = pk_shares
                        self.thepk = thpk
                        self.thesk = share_m
                        self.round = round + 1
                        self.start_round = self.round
                        # print(self.id, ":[", self.thesk, self.thepks, self.thepk, "]")
                        p_etime = time.time()
                        if self.logger != None:
                            self.logger.info('Node %d read a proofchain using %f sec' % (self.id, p_etime-p_stime))
                        print('Node %d read a proofchain using %f sec' % (self.id, p_etime-p_stime))
                        break
                        # print(pid, "recv from", sender, thpk)
                    except Exception as e:
                        traceback.print_exc(e)
                        continue

        #self._recv_thread = gevent.spawn(_recv_loop)
        self._recv_thread = Greenlet(_recv_loop)
        self._recv_thread.start()


        # print("new nodes", self.id, "start to parsing configuration.")

        wait_for_config()
        self.s_time = time.time()
        if self.logger != None:
            self.logger.info('Node %d starts to run at time:' % self.id + str(self.s_time))
        while True:
            # For each round...
            #gevent.sleep(0)
            # if self.id in {3, 4, 5, 6}:
            #     break
            if self.id in self.configchain[self.round]:
                start = time.time()

                r = self.round
                # print("nodes", self.id, "start round", r)
                self.logger.info('nodes start round %d' % int(r))
                if r not in self._per_round_recv:
                    self._per_round_recv[r] = Queue()

                # Select B transactisons (TODO: actual random selection)
                tx_to_send = []
                for _ in range(self.B):
                    tx_to_send.append(self.transaction_buffer.get_nowait())

                def membership_tx(o, p):
                    return 'Membership TX:' + str(o) + ':' + str(p)

                if (r != 0) and (r % self.reconfig == 0):
                    #add membership tx
                    count = 0
                    while count < self.B_m:
                        try:
                            (mem, op) = self.mem_buffer.get_nowait()
                            print(self.id, self.configchain[r - 1], mem, op, max(self.configchain[r-1]))
                            if op == 'J' and int(mem) <= max(self.configchain[r-1]):
                                continue
                            if op == 'L' and int(mem) not in self.configchain[r-1]:
                                continue
                            tx_to_send.append(membership_tx(mem, op))
                            count += 1
                        except Exception as e:
                            break
                            # traceback.print_exc(e)

                def _make_send(r):
                    def _send(j, o):
                        self._send(j, (r, o))
                    return _send

                # print(self.id, "start round", r)
                send_r = _make_send(r)
                recv_r = self._per_round_recv[r].get
                new_tx = self._run_round(r, tx_to_send, send_r, recv_r)
                '''
                if new_tx is None:
                    self.e_time = time.time()
                    if self.logger != None:
                        self.logger.info("node %d breaks in %f seconds with total delivered Txs %d, latency: %f, tps: %f" % (
                        self.id, self.e_time - self.s_time, self.txcnt,
                        (self.e_time - self.s_time)/(self.round - self.start_round), self.txcnt/(self.e_time - self.s_time)))

                    print("node %d breaks in %f seconds with total delivered Txs %d, latency: %f, tps: %f" % (
                        self.id, self.e_time - self.s_time, self.txcnt,
                        (self.e_time - self.s_time) / (self.round + 1 - self.start_round),
                        self.txcnt / (self.e_time - self.s_time)))
                    break
                '''
                    # gevent.sleep(100)
                end = time.time()

                # if self.logger != None:
                #     self.logger.info('ACS Block Delay at Node %d: ' % self.id + str(end - start))

                self.round += 1  # Increment the round
                if self.round > self.K:
                    self.e_time = time.time()
                    tps = self.txcnt / (self.e_time - self.s_time)
                    latency = (self.e_time - self.s_time) / (self.round - self.start_round)
                    self.e_time = time.time()
                    if self.logger != None:
                        self.logger.info(
                            "node %d breaks in %f seconds with total delivered Txs %d, latency: %f, tps: %f" % (
                                self.id, self.e_time - self.s_time, self.txcnt,
                                latency, tps))

                    print("node %d breaks in %f seconds with total delivered Txs %d, latency: %f, tps: %f" % (
                        self.id, self.e_time - self.s_time, self.txcnt,
                        latency, tps))
                    for i in range(self.N_all):
                        if i != self.id:
                            self._send(i, (-3, ('HALT', self.round)))
                    self._send(0, (-4, ('DATA', (tps, latency))))
                    if self.id != 0:
                        self.leave_signal.set()
                        break# Only run one round for now
                    else:
                        break

            elif self.id in self.C_g:
                # gevent.sleep(100)
                # print(self.id, "has left")
                self.e_time = time.time()
                tps = self.txcnt / (self.e_time - self.s_time)
                latency = (self.e_time - self.s_time)/(self.round - self.start_round)
                if self.logger != None:
                    self.logger.info("node %d breaks in %f seconds with total delivered Txs %d, latency: %f, tps: %f" % (
                        self.id, self.e_time - self.s_time, self.txcnt,
                        latency, tps))

                print("node %d breaks in %f seconds with total delivered Txs %d, latency: %f, tps: %f" % (
                    self.id, self.e_time - self.s_time, self.txcnt,
                    latency,tps))
                self._send(0, (-4, ('DATA', (tps, latency))))

                break
                # return

        def wait_for_halt():
            while True:
                gevent.sleep(0)
                try:
                    sender, msg = self.halt_recv.get(0.001)
                    gevent.sleep(2)
                    self.leave_signal.set()
                    break
                except Exception as e:
                    gevent.sleep(0)
                    continue
        def wait_for_data():
            while True:
                gevent.sleep(0)
                try:
                    sender, msg = self.data_recv.get(0.001)
                    _, (tps, latency) = msg
                    if self.logger != None:
                        self.logger.info("node %d: tps-- %f ; latency-- %f" % (sender, tps, latency))
                    # print("node %d: tps-- %f ; latency-- %f" % (sender, tps, latency))
                    self.data[0].append(tps)
                    self.data[1].append(latency)
                    # print(self.N_all, self.data[0], len(self.data[0]))
                    if len(self.data[0]) == self.N_all:
                        tps_avg = statistics.mean(self.data[0])
                        l_avg = statistics.mean(self.data[1])
                        if self.logger != None:
                            self.logger.info("========average========")
                            self.logger.info('tps: %f, latency: %f' % (tps_avg, l_avg))
                        print("========average========")
                        print('tps: %f, latency: %f' % (tps_avg, l_avg))

                        self.leave_signal.set()
                        break
                except Exception as e:
                    gevent.sleep(0)
                    continue
        if self.id != 0:
            gevent.spawn(wait_for_halt)
        else:
            gevent.spawn(wait_for_data)
        self.leave_signal.wait()
        gevent.sleep(10)

        """

        if self.logger != None:
            self.e_time = time.time()
            self.logger.info("node %d breaks in %f seconds with total delivered Txs %d" % (self.id, self.e_time-self.s_time, self.txcnt))
        else:
            print("node %d breaks" % self.id)
        """

        return self.round

        #self._recv_thread.join(timeout=2)

    #

    def _run_round(self, r, tx_to_send, send, recv):
        """Run one protocol round.
        :param int r: round id
        :param tx_to_send: Transaction(s) to process.
        :param send:
        :param recv:
        """
        s_time = time.time()
        # Unique sid for each round
        sid = self.sid + ':' + str(r)
        pid = self.id
        C = self.configchain[r]
        N = self.N_o
        f = self.f_o
        l = self.l_o

        thepk_o = self.thepk
        # if r % self.reconfig == 0:
        #     print("=====", pid, thepk_o)



        print(self.id, "start to run round", r, "C:", C, "N:", N)
        pb_recvs = [Queue() for _ in range(N)]
        vacs_recv = Queue()
        tpke_recv = Queue()
        adkr_recv = Queue()
        adkrn_recv = Queue()

        my_pb_input = Queue(1)

        # pb_proof_output = Queue(1)
        pb_proofs = dict()

        vacs_input = Queue(1)
        vacs_output = Queue(1)
        left_output = Queue(1)
        adkr_output = Queue(1)
        if r != 1 and r% self.reconfig == 1:
            self.salvagset[r - 1] = defaultdict()
        recv_queues = BroadcastReceiverQueues(
            ACS_PRBC=pb_recvs,
            ACS_VACS=vacs_recv,
            TPKE=tpke_recv,
            ADKR_OLD=adkr_recv,
            ADKR_NEW=adkrn_recv
        )
        # tracemalloc.start()
        bc_recv_loop_thread = Greenlet(broadcast_receiver_loop, recv, recv_queues, C, self.logger)
        bc_recv_loop_thread.start()

        # print(pid, r, 'tx_to_send:', tx_to_send)
        #if self.logger != None:
        #    self.logger.info('Commit tx at Node %d:' % self.id + str(tx_to_send))

        pb_threads = [None] * N

        def _setup_pb(j):
            """Setup the sub protocols RBC, BA and common coin.
            :param int j: Node index for which the setup is being done.
            """

            def pb_send(k, o):
                """Reliable send operation.
                :param k: Node to send.
                :param o: Value to send.
                """
                send(k, ('ACS_PRBC', C[j], o))

            # Only leader gets input
            pb_input = my_pb_input.get if C[j] == pid else None

            pb_thread = gevent.spawn(provablebroadcast, sid+'PB'+str(r)+str(C[j]), pid, C,
                                     N, f, l, self.sPK2s, self.sSK2, C[j], pb_input,
                                     self.pb_value_outputs[r][j].put_nowait,
                                     recv=pb_recvs[j].get, send=pb_send, logger=None)

            def wait_for_pb_proof():
                proof = pb_thread.get()
                try:
                    pb_proofs[sid+'PB'+str(r)+str(C[j])] = proof
                    self.pb_proof_output[r].put_nowait(proof)
                except TypeError as e:
                    print(e)
                    #return False
            # wait for pb proof, only when I am the leader
            if C[j] == pid:
                gevent.spawn(wait_for_pb_proof)

            return pb_thread

        # N instances of PB
        for j in range(N):
            # print(self.id, "start to set up pb %d" % C[j])
            pb_threads[j] = _setup_pb(j)



        # One instance of (validated) ACS
        #print("start to set up VACS")
        def vacs_send(k, o):
            """Threshold encryption broadcast."""
            """Threshold encryption broadcast."""
            send(k, ('ACS_VACS', '', o))

        def vacs_predicate(j, vj, t):
            # print("v_p", pb_proofs.keys())
            # print("the j is", j)
            if t == 1:
                prbc_sid = sid + 'PB' + str(r) + str(C[j])
            else:
                prbc_sid = self.sid + ':' + str(r-1) + 'PB' + str(r-1) + str(C[j])
            try:
                proof = vj
                if prbc_sid in pb_proofs.keys():
                    try:
                        _prbc_sid, _digest, _sigmas = proof
                        # print(print("the j is", j, C[j]), prbc_sid, _prbc_sid)
                        assert prbc_sid == _prbc_sid
                        _, digest, _ = pb_proofs[prbc_sid]
                        assert digest == _digest
                        return True
                    except AssertionError:
                        print(pid, "1 Failed to verify proof for RBC", t, prbc_sid, _prbc_sid)
                        return False
                # print("sid:", prbc_sid)
                assert pb_validate(prbc_sid, N, f, l, self.sPK2s, proof)
                pb_proofs[prbc_sid] = proof
                return True
            except AssertionError:
                print(pid, "2 Failed to verify proof for RBC")
                return False
        if self.debug:
            vacs_thread = Greenlet(speedmvbacommonsubset, sid + 'VACS' + str(r), pid, C, r, self.reconfig, N, f, l, self.last_pb_proof,
                               self.sPK2s, self.sSK2, self.thepks, self.thesk, self.g1, 's',
                               vacs_input.get, vacs_output.put_nowait, left_output.put_nowait,
                               vacs_recv.get, vacs_send, vacs_predicate, logger=self.logger)
        else:
            vacs_thread = Greenlet(speedmvbacommonsubset, sid + 'VACS' + str(r), pid, C, r, self.reconfig, N, f, l,
                                   self.last_pb_proof,
                                   self.sPK2s, self.sSK2, self.thepks, self.thesk, self.g1, 's',
                                   vacs_input.get, vacs_output.put_nowait, left_output.put_nowait,
                                   vacs_recv.get, vacs_send, vacs_predicate, logger=None)
        vacs_thread.start()

        # One instance of TPKE
        def tpke_bcast(o):
            """Threshold encryption broadcast."""
            for i in C:
                send(i, ('TPKE', '', o))

        # One instance of ACS pid, N, f, prbc_out, vacs_in, vacs_out
        if (r % self.reconfig != 1 or r == 1) and r != 0:
            dumboacs_thread = Greenlet(speedydumbocommonsubset, pid, N, f, l, C, r, self.reconfig, self.salvagset[r-1],
                           [_.get for _ in self.pb_value_outputs[r]], [_.get_nowait for _ in self.pb_value_outputs[r-1]],
                           self.pb_proof_output[r].get,
                           vacs_input.put_nowait,
                           vacs_output.get, self.logger)
        else:
            dumboacs_thread = Greenlet(speedydumbocommonsubset, pid, N, f, l, C, r, self.reconfig, self.salvagset[r-1],
                           [_.get for _ in self.pb_value_outputs[r]], None,
                           self.pb_proof_output[r].get,
                           vacs_input.put_nowait,
                           vacs_output.get, self.logger)

        dumboacs_thread.start()

        '''
        _output = honeybadger_block(pid, N, f, self.ePKS, self.eSK,
                          propose=json.dumps(tx_to_send),
                          acs_put_in=my_pb_input.put_nowait, acs_get_out=dumboacs_thread.get,
                          tpke_bcast=tpke_bcast, tpke_recv=tpke_recv.get,logger=self.logger)

        '''
        my_pb_input.put_nowait(json.dumps(tx_to_send))
        acs_get_out, pb_left, count_t = dumboacs_thread.get()
        # print(acs_get_out)
        self.last_pb_proof = left_output.get()
        self.salvagset[r] = pb_left


        """
        if r >= 2:
            try:
                del self.salvagset[r-2]
                self.salvagset = copy.copy(self.salvagset)
                del self.pb_value_outputs[r-2]
                self.pb_value_outputs = copy.copy(self.pb_value_outputs)
                del self.pb_proof_output[r-2]
                self.pb_proof_output = copy.copy(self.pb_proof_output)
            except Exception as e:
                print((self.id, r))
                pass
        """
        if r >= 2:
            try:
                self.salvagset[r-2] = None
                # self.salvagset = copy.copy(self.salvagset)
                self.pb_value_outputs[r-2] = None
                # self.pb_value_outputs = copy.copy(self.pb_value_outputs)
                self.pb_proof_output[r-2] = None
                # self.pb_proof_output = copy.copy(self.pb_proof_output)
            except Exception as e:
                print("Excption!", (self.id, r))
                pass


        del left_output
        del pb_left
        # print("left pb vlues:", self.salvagset[r].keys(), "left pb proofs:", left_vector.keys())
        count = 0
        decryptions = []
        for i, v in enumerate(acs_get_out):
            if v is None:
                continue
            count += 1
            # print(type(v))
            # plain = pickle.loads(v)
            decryptions.append(v)
        # if self.id == 4: print("decryptions", decryptions)
        block = set()
        mem_set = set()
        for batch in tuple(decryptions):
            decoded_batch = json.loads(batch)
            for tx in decoded_batch:
                block.add(tx)
                if tx.find('Membership') >= 0:
                    mem_set.add(tx)


        new_tx = list(block)
        # if self.id == 4: print(new_tx)
        new_mem = list(mem_set)
        tx_cnt = str(new_tx).count("Dummy TX")
        tx_cnt += count_t * self.B
        mem_cnt = str(new_tx).count("Membership TX")
        self.txcnt += tx_cnt + mem_cnt

        if r != 0 and r % self.reconfig == 0:
            adkr_s_time = time.time()
            config_delata = defaultdict(lambda: set())
            for i in range(len(new_mem)):
                t = str(new_mem[i]).split(':')
                config_delata[t[2]].add(t[1])
            # print(config_delata)
            for i in C:
                if str(i) not in config_delata['L']:
                    self.configchain[r+1].append(int(i))
            for i in config_delata['J']:
                # print(self.id, i)
                if i not in self.configchain[r+1]:
                    self.configchain[r+1].append(int(i))
            self.configchain[r+1] = sorted(self.configchain[r+1])
            # print(self.configchain[r+1])

            self.N_o = len(self.configchain[r+1])
            self.l_o = self.l_n
            self.f_o = int((self.N_o - 2 * self.l_o - 1) / 3)

            def adkr_send(k, o):
                send(k, ('ADKR_OLD', '', o))
            # using 25519 in pypairing

            if self.ec == 'r':
                print("no such option")
            #using secp256k1 in charm

            else:
                if self.debug:
                    gevent.spawn(ADKR_old_c, sid + 'ADKR' + str(r), pid, self.configchain, self.l_n, self.f_g, r, self.g1, self.ec,
                             self.sPK2s, self.sSK2,
                             self.ePKS, self.eSK, self.thesk, 0, self.thepks, adkr_output.put_nowait, adkr_send, adkr_recv.get, logger=self.logger)
                else:
                    gevent.spawn(ADKR_old_c, sid + 'ADKR' + str(r), pid, self.configchain, self.l_n, self.f_g, r,
                                 self.g1, self.ec,
                                 self.sPK2s, self.sSK2,
                                 self.ePKS, self.eSK, self.thesk, 0, self.thepks, adkr_output.put_nowait, adkr_send, adkr_recv.get)
            (script, Sigma) = adkr_output.get()

            adkr_e_time = time.time()
            print('adkr running time: %f' % (adkr_e_time - adkr_s_time))
            self.logger.info('adkr running time: %f' % (adkr_e_time-adkr_s_time))

            if self.id in self.configchain[r + 1]:
                (pk_shares_s, share_e, thpk_s, C_n) = script
                thpk = group.deserialize(thpk_s)
                pk_shares = []
                for itme in pk_shares_s:
                    pk_shares.append([itme[0], group.deserialize(itme[1])])
                share_m = self.eSK.raw_decrypt(share_e[self.configchain[r + 1].index(self.id)])
                self.thepks = pk_shares
                self.thepk = thpk
                self.thesk = share_m
            self.proofchain[r] = (script, Sigma)
            for i in config_delata['J']:
                self._send(int(i), (-2, ('ADKR_NEW', r, dill.dumps(self.proofchain))))
        else:
            self.configchain[r + 1] = self.configchain[r]
            self.N_o = len(self.configchain[r])
            self.l_o = self.l_n
            self.f_o = self.f_g
        e_time = time.time()
        tps = self.txcnt / (e_time - self.s_time)
        latency = (e_time - self.s_time) / (self.round+1 - self.start_round)

        if self.logger != None:
            self.logger.info('Node %d Delivers ACS Block in Round %d with having %d TXs' % (self.id, r, tx_cnt + mem_cnt))
            self.logger.info('round %d time: %f' %(r, e_time-s_time))
        print("Node", self.id, "Delivers ACS Block in Round", r, "with having",  tx_cnt + mem_cnt, "TXs")
        print("this round time:", e_time-s_time)
        if self.logger != None:
            self.logger.info(
                'Node %d counting so-far tps: %f, latency %f' % (self.id, tps, latency))
        print('Node %d counting so-far tps: %f, latency %f' % (self.id, tps, latency))

        dumboacs_thread.kill()

        bc_recv_loop_thread.kill()
        vacs_thread.kill()

        for j in range(N):
            pb_threads[j].kill()
        """
        snapshot = tracemalloc.take_snapshot()
        top_s = snapshot.statistics('traceback')
        if self.id == 0:
            print('[top 10]')
            for stat in top_s[:10]:
                for line in stat.traceback.format():
                    print(line)
                print("*"*30)
                print("%s mem blcoks: %.1f kiB" % (stat.count, stat.size/1024))
        """
        return list(block)

# TODO： make help and callhelp threads to handle the rare cases when vacs (vaba) returns None