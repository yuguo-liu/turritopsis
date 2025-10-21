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
from crypto.ecdsa.ecdsa import ecdsa_vrfy, ecdsa_sign
from adkr.keyrefersh.core.poly_misc_charm import interpolate_g_at_x
from speedydumbo_dy.core.speedydumbocommonsubset import speedydumbocommonsubset
from speedydumbo_dy.core.provablebroadcast import provablebroadcast
from speedydumbo_dy.core.validators import pb_validate
from dumbobft.core.speedmvbacommonsubset_dy import speedmvbacommonsubset
from adkr.keyrefersh.core.adkr_old_charm import ADKR_old_c
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


BroadcastReceiverQueues = namedtuple(
    'BroadcastReceiverQueues', ('ADKR_NEW', 'ADKR_OLD'))


def broadcast_receiver_loop(recv_func, recv_queues, C):
    while True:
        #gevent.sleep(0)
        sender, (tag, j, msg) = recv_func()

            # print('recv_sd', sender, tag)
        if tag not in BroadcastTag.__members__:
            # TODO Post python 3 port: Add exception chaining.
            # See https://www.python.org/dev/peps/pep-3134/
            raise UnknownTagError('Unknown tag: {}! Must be one of {}.'.format(
                tag, BroadcastTag.__members__.keys()))
        recv_queue = recv_queues._asdict()[tag]

        try:
            if tag == 'AKDR_NEW':
                recv_queue.put_nowait((sender, (tag, j, msg)))
            else:
                recv_queue.put_nowait((sender, msg))
        except AttributeError as e:
            print("error", sender, (tag, j, msg))
            traceback.print_exc(e)


class Adkrround():
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

    def __init__(self, sid, pid, B, B_m, l, f, C_g, N_all, reconfig, l_list, g1, ec, sPK2s, sSK2, ePK, eSK, thpk, thpks, thsk, send, recv, K=3, mute=False, debug=None):
        self.sid = sid
        self.id = pid
        self.B = B
        self.B_m = B_m
        self.C_g = C_g
        self.N_g = len(C_g)
        self.f_g = f
        self.C_n = C_g
        self.N_n = len(self.C_n)
        self.l_n = l
        self.f_n = f
        self.C_o = C_g
        self.N_o = len(self.C_n)
        self.f_o = f
        self.l_o = l

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
        self.script_output = defaultdict(lambda: Queue(1))
        self.last_pb_proof = defaultdict()
        self.round = 0  # Current block number
        self.start_round = 0
        self.transaction_buffer = Queue()
        self.mem_buffer = Queue()
        self._per_round_recv = {}  # Buffer of incoming messages
        self.avg = 0
        self.data_recv = Queue()
        self.data = defaultdict(lambda :list())
        self.K = K

        self.s_time = 0
        self.e_time = 0
        self.sum_time = 0
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


    def run_bft(self):
        """Run the Dumbo protocol."""

        def _recv_loop():
            """Receive messages."""
            #print("start recv loop...")
            while True:
                #gevent.sleep(0)
                try:
                    (sender, (r, msg)) = self._recv()
                    # print(self.id, "recv_sdumobo", r, msg[0])
                    #self.logger.info('recv1' + str((sender, o)))
                    # Maintain an *unbounded* recv queue for each epoch
                    if r == -4:
                        # print("reciv!!!!!!!!!")
                        self.data_recv.put_nowait((sender, msg))
                    elif r not in self._per_round_recv:
                        self._per_round_recv[r] = Queue()
                    # Buffer this message
                    self._per_round_recv[r].put_nowait((sender, msg))
                except Exception as e:
                    # print(e)
                    continue


        #self._recv_thread = gevent.spawn(_recv_loop)
        self._recv_thread = Greenlet(_recv_loop)
        self._recv_thread.start()


        # print("new nodes", self.id, "start to parsing configuration.")

        self.s_time = time.time()
        if self.logger != None:
            self.logger.info('Node %d starts to run at time:' % self.id + str(self.s_time))
        while True:

            start = time.time()

            r = self.round
            # print("nodes", self.id, "start round", r)
            if r not in self._per_round_recv:
                self._per_round_recv[r] = Queue()

            def _make_send(r):
                def _send(j, o):
                    self._send(j, (r, o))
                return _send

            # print(self.id, "start round", r)
            send_r = _make_send(r)
            recv_r = self._per_round_recv[r].get
            pt, ps = self._run_round(r, send_r, recv_r)

                # gevent.sleep(100)
            end = time.time()

            # if self.logger != None:
            #     self.logger.info('ACS Block Delay at Node %d: ' % self.id + str(end - start))

            self.round += 1  # Increment the round
            if self.round > self.K:

                run_avg  = self.sum_time / self.K

                self.e_time = time.time()
                if self.logger != None:
                    self.logger.info(
                        "node %d breaks in %f seconds with %d round, adkr_old avg time: %f, pc size: %d, verify time: %f" % (
                            self.id, self.e_time - self.s_time, self.K, run_avg, ps, pt))

                print(
                        "node %d breaks in %f seconds with %d round, adkr_old avg time: %f, pc size: %d, verify time: %f" % (
                            self.id, self.e_time - self.s_time, self.K, run_avg, ps, pt))

                self._send(0, (-4, ('DATA', (run_avg, ps, pt))))
                gevent.sleep(2)
                if self.id != 0:
                    return self.round# Only run one round for now
                else:
                    break

                # return


        def wait_for_data():
            while True:
                gevent.sleep(0)
                try:
                    sender, msg = self.data_recv.get(0.001)
                    _, (a, ps, pt) = msg
                    if self.logger != None:
                        self.logger.info("node %d: adkro time-- %f ; size-- %f; verify time-- %f" % (sender, a, ps, pt))
                    # print("node %d: tps-- %f ; latency-- %f" % (sender, tps, latency))
                    self.data[0].append(a)
                    self.data[1].append(ps)
                    self.data[2].append(pt)
                    # print(self.N_all, self.data[0], len(self.data[0]))
                    if len(self.data[0]) == self.N_all:
                        o_avg = statistics.mean(self.data[0])
                        ps_avg = statistics.mean(self.data[1])
                        pt_avg = statistics.mean(self.data[2])
                        if self.logger != None:
                            self.logger.info("========average========")
                            self.logger.info('adkro time: %f, size: %f, verify time: %f' % (o_avg, ps_avg, pt_avg))
                        print("========average========")
                        print('adkro time: %f, size: %f, verify time: %f' % (o_avg, ps_avg, pt_avg))

                        self.leave_signal.set()
                        break
                except Exception as e:
                    gevent.sleep(0)
                    continue

        gevent.spawn(wait_for_data())
        self.leave_signal.wait()
        return self.round

    #
    def _run_round(self, r, send, recv):
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

        def wait_for_config():

            def verify_sig(Sigma, script, C_o):
                # print(len(Sigma))
                # print(C_o)
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
            p_etime = 0
            p_stime = 0
            # print(self.id, self.C_g, self.f_o)

            if r != 0:
                try:
                    round, proof_chain_r = self.script_output[r].get(0.000001)
                    p_stime = time.time()
                    pc_size = sys.getsizeof(proof_chain_r)
                    print('pc size for round %d is %d' % (round, pc_size))
                    self.logger.info('pc size for round %d is %d' % (round, pc_size))
                    proof_chain = dill.loads(proof_chain_r)
                    # print(self.id, "recv a config msg from", sender)
                    for c in proof_chain.keys():
                        # proof_chain[c] contains script for config[c+1], signed by config[c]
                        if c == 0:
                            self.configchain[0] = self.C_g
                        (script, Sigma) = proof_chain[c]
                        (pk_shares_s, share_e, thpk_s, C_n) = script
                        # print("Cn is, ", C_n)
                        self.configchain[c+1] = C_n
                        # self.configchain[c] = script[3]
                        thpk = group.deserialize(thpk_s)
                        assert thpk == self.g1 ** (self.f_g + 1)
                        pk_shares = []
                        for itme in pk_shares_s:
                            pk_shares.append([itme[0], group.deserialize(itme[1])])
                        # print("c:", c, "member:", self.configchain[c - self.reconfig])
                        if not verify_sig(Sigma, (pk_shares, share_e, thpk, C_n),
                                          self.configchain[c]):
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
                    print(self.id, "config verify passed!!")
                    share_m = self.eSK.raw_decrypt(share_e[self.C_o.index(self.id)])
                    self.thepks = pk_shares
                    self.thepk = thpk
                    self.thesk = share_m
                    self.round = round + 1
                    # self.start_round = self.round
                    # print(self.id, ":[", self.thesk, self.thepks, self.thepk, "]")
                    p_etime = time.time()
                    if self.logger != None:
                        self.logger.info('Node %d read a proofchain using %f sec' % (self.id, p_etime - p_stime))
                    print('Node %d read a proofchain using %f sec' % (self.id, p_etime - p_stime))
                    if round == self.K - 1:

                        return (p_etime-p_stime), pc_size
                    else:
                        return None, None
                    # print(pid, "recv from", sender, thpk)
                except Exception as e:
                    traceback.print_exc(e)

            return None, None



        thepk_o = self.thepk
        # if r % self.reconfig == 0:
        #     print("=====", pid, thepk_o)

        C = self.C_g
        N = self.N_g
        f = self.f_g
        l = self.l_o
        adkr_recv = Queue()
        adkrn_recv = Queue()

        left_output = Queue(1)
        adkr_output = Queue(1)

        recv_queues = BroadcastReceiverQueues(
            ADKR_OLD=adkr_recv,
            ADKR_NEW=adkrn_recv
        )

        bc_recv_loop_thread = Greenlet(broadcast_receiver_loop, recv, recv_queues, C)
        bc_recv_loop_thread.start()
        pt, ps = wait_for_config()
        if r == self.K:
            return pt, ps


        print(self.id, "start to run round", r, "C:", C, "N:", N)
        self.configchain[r+1] = self.configchain[r]
        # print(self.configchain[r+1])

        self.N_o = len(self.configchain[r+1])
        self.l_o = self.l_n
        self.f_o = int((self.N_o - 2 * self.l_o - 1) / 3)

        s_time = time.time()
        def adkr_send(k, o):
            send(k, ('ADKR_OLD', '', o))
        # using 25519 in pypairing
        if self.ec == 'r':
            print("no such option")
        #using secp256k1 in charm
        else:
            if self.debug == True:
                gevent.spawn(ADKR_old_c, sid + 'ADKR' + str(r), pid, self.configchain, self.l_n, self.f_g, r, self.g1, self.ec,
                         self.sPK2s, self.sSK2,
                         self.ePKS, self.eSK, 0, 0, [], adkr_output.put_nowait, adkr_send, adkr_recv.get, logger=self.logger)
            else:
                gevent.spawn(ADKR_old_c, sid + 'ADKR' + str(r), pid, self.configchain, self.l_n, self.f_g, r, self.g1,
                             self.ec,
                             self.sPK2s, self.sSK2,
                             self.ePKS, self.eSK, 0, 0, [], adkr_output.put_nowait, adkr_send, adkr_recv.get)
        (script, Sigma) = adkr_output.get()
        self.proofchain[r] = (script, Sigma)
        self.script_output[r+1].put_nowait((r, dill.dumps(self.proofchain)))
        e_time = time.time()

        self.logger.info('run round %d adkr-old taking %f sec' % (r, e_time-s_time))
        print('run round %d adkr round taking %f sec' % (r, e_time-s_time))
        self.sum_time += e_time - s_time
        bc_recv_loop_thread.kill()

        return None, None

# TODO： make help and callhelp threads to handle the rare cases when vacs (vaba) returns None