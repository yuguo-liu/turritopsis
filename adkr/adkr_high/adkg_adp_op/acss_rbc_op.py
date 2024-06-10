# coding=utf-8
from collections import defaultdict
import os
import gevent
from gevent import monkey
import hashlib
import math
from adkr.acss.core.reliablebroadcast import encode, decode, ceil, merkleTree, merkleVerify, getMerkleBranch
from utils.core.betterpairing import G1, ZR
from pickle import dumps, loads
import phe
from adkr.acss.core.polynomial_pairing import polynomials_over_BN as polynomials_over_BN_N
from utils.core.serializer import serialize, deserialize
import traceback, time
from utils.core.bls_bn import sign, verify_share, verify_signature, hash_message, combine_shares

from utils.core.merkleTree import encode, decode
from utils.core.merkleTree import merkleTree, getMerkleBranch, merkleVerify
import multiprocessing
from utils.core.serializer import serialize_G2,deseralize_G2
stop = 0

def hash(x):
    assert isinstance(x, (str, bytes))
    try:
        x = x.encode()
    except AttributeError:
        pass
    return hashlib.sha256(x).digest()

def prove_knowledge_of_encrypted_dlog(g, x, pk, g_to_the_x=None):
    if g_to_the_x is None:
        Y = g ** x
    else:
        Y = g_to_the_x
    r = pk.get_random_lt_n()
    c = pk.encrypt(int(x), r_value=r).ciphertext(be_secure=False)
    # Todo: see if this limitation is libarary-specific. Maybe use a slightly larget N?
    u = pk.get_random_lt_n() // 3  # maximum valid value we can encrypt
    T = g ** u
    e = ZR.hash(dumps([pk, serialize(g), serialize(Y), c, serialize(T)]))
    z = u + int(e) * int(x)
    s = pk.get_random_lt_n()
    e_u = pk.encrypt(u, r_value=s)
    w = (pow(r, int(e), pk.nsquare) * s) % pk.nsquare
    proof = [serialize(T), z, e_u, w]
    return [serialize(Y), c, proof]

def verify_knowledge_of_discrete_log(pk, g, Y, c, proof):
    T, z, e_u, w = proof
    e = ZR.hash(dumps([pk, serialize(g), Y, c, T]))
    # be_secure is default true and adds a randomizing factor to the ciphertext as a failsafe.
    # we need it turned off so that the calculations will be correct
    c_e = pow(c, int(e), pk.nsquare)
    return deserialize(T) == (g ** z) * (deserialize(Y) ** (-e)) and \
           (e_u.ciphertext(be_secure=False) * c_e) % pk.nsquare == pk.encrypt(z, r_value=w).ciphertext(
        be_secure=False)


def predicate(C_n, pid, ePKs, g, comms, encryptions, proofs):
    try:
        for i in range(len(C_n)):
            # gevent.sleep(0)
            # if dealer == 2: print(PKs[C_n[i]], g, comms[i], encryptions[i], proofs[i])
            if not verify_knowledge_of_discrete_log(ePKs[C_n[i]], g, comms[i], encryptions[i], proofs[i]):
                print(pid, "verify failed", C_n[i], "for dealer")
                return False
            # pass
        return True
    except Exception as e:
        print(pid, "Failed to verify acss script:", e)

def completesecretsharing(sid, pid, N_o, f_o, C_o, N_n, f_n, C_n, g, dealer, ePKs, eSK, thpk, thsk, input, output, receive, send, logger):
    """ACSS with dcr

    :param int pid: ``0 <= pid < N``
    :param int N:  at least 3
    :param int f: fault tolerance, ``N >= 3f + 1``
    :param int dealer: ``0 <= leader < N``
    :param input: if ``pid == leader``, then :func:`input()` is called
        to wait for the input value
    :param receive: :func:`receive()` blocks until a message is
        received; message is of the form::

            (i, (tag, ...)) = receive()


    :param send: sends (without blocking) a message to a designed
        recipient ``send(i, (tag, ...))``

    :return str: ``m`` after receiving :math:`2f+1` ``READY`` messages
        and :math:`N-2f` ``ECHO`` messages

    """
    # print(pid, "---------------start", sid)
    # assert N >= 3*f + 1
    # assert f >= 0
    # assert 0 <= dealer < N
    # assert 0 <= pid < N
    K_o               = N_o - 2 * f_o  # Need this many to reconstruct. (# noqa: E221)
    EchoThreshold   = N_o - f_o      # Wait for this many ECHO to send READY. (# noqa: E221)
    ReadyThreshold  = N_o - 2 * f_o      # Wait for this many READY to amplify READY. (# noqa: E221)
    OutputThreshold = N_o - f_o  # Wait for this many READY to output
    SignThreshold = 2 * f_o + 1
    # logger.info('node %s starts ss %s' % (pid, dealer))
    # group = PairingGroup('BN256')
    # NOTE: The above thresholds  are chosen to minimize the size
    # of the erasure coding stripes, i.e. to maximize K.
    # The following alternative thresholds are more canonical
    # (e.g., in Bracha '86) and require larger stripes, but must wait
    # for fewer nodes to respond
    #   EchoThreshold = ceil((N + f + 1.)/2)
    #   K = EchoThreshold - f

    def decode_output(roothash):
        # Rebuild the merkle tree to guarantee decoding is correct
        m = decode(K_o, N_o, stripes[roothash])
        _stripes = encode(K_o, N_o, m)
        _mt = merkleTree(_stripes)
        _roothash = _mt[1]
        # TODO: Accountability: If this fails, incriminate leader
        assert _roothash == roothash
        return m
    def broadcast(o):
        for i in C_o:
            send(i, o)
        # send(-1, o)
    s_time = time.time()

    if pid == dealer:
        # The leader erasure encodes the input, sending one strip to each participant
        m = input()  # block until an input is received

        # logger.info('dealer %s get acss input %d' % (pid, m))

        poly = polynomials_over_BN_N(ZR)
        phi = poly.random(f_n, m)
        # logger.info('dealer %s get poly phi %d' % (pid, phi(0)))
        # if pid == r % 9 or pid == (r+1) % 9:
        #    outputs = [prove_knowledge_of_encrypted_dlog(g, phi(C_n[i] + 1), PKs[C_n[0]]) for i in range(N_n)]
        # else:
        # outputs = [prove_knowledge_of_encrypted_dlog(g, phi(C_n[i] + 1), ePKs[C_n[i]]) for i in range(N_n)]


        # outputs = [None for _ in range(N_n)]
        # t = []

        # for i in range(N_n):
        #     res = pool.apply_async(dummy, args=(i,))
        #     outputs.append(res)
        outputs = [prove_knowledge_of_encrypted_dlog(g, phi(C_n[i] + 1), ePKs[C_n[i]]) for i in range(N_n)]
        msg = dumps([[outputs[i][j] for i in range(N_n)] for j in range(3)])
        # print("dealer", dealer, "gen!")
        # logger.info('node %s generate ss %s output' % (pid, dealer))
        stripes = encode(K_o, N_o, msg)

        mt = merkleTree(stripes)  # full binary tree
        roothash = mt[1]
        for i in range(N_o):
            branch = getMerkleBranch(i, mt)
            send(C_o[i], ('VAL', roothash, branch, stripes[i]))
        # print(pid, "leader send val")


    # TODO: filter policy: if leader, discard all messages until sending VAL

    fromLeader = None
    stripes = defaultdict(lambda: [None for _ in range(N_o)])
    echoCounter = defaultdict(lambda: 0)
    echoSenders = set()  # Peers that have sent us ECHO messages
    ready = defaultdict(set)
    readySent = False
    readySenders = set()  # Peers that have sent us READY messages

    while True:  # main receive loop
        # print(pid, "start acss")
        sender, msg = receive()
        # print(pid, "recv", (sender, msg[0]))
        if msg[0] == 'VAL' and fromLeader is None:
            # Validation
            (_, roothash, branch, stripe) = msg
            if sender != dealer:
                print("VAL message from other than leader:", sender)
                continue
            try:
                assert merkleVerify(N_o, stripe, roothash, branch, C_o.index(pid))
            except Exception as e:
                print("Failed to validate VAL message:", e)
                continue

            # Update
            fromLeader = roothash
            broadcast(('ECHO', roothash, branch, stripe))

        elif msg[0] == 'ECHO':
            (_, roothash, branch, stripe) = msg
            # Validation
            if roothash in stripes and stripes[roothash][C_o.index(sender)] is not None:
                print("Redundant ECHO2")
                continue
            if sender in echoSenders:
                print("Redundant ECHO3")
                continue
            try:
                assert merkleVerify(N_o, stripe, roothash, branch, C_o.index(sender))
            except AssertionError as e:
                print("Failed to validate ECHO message:", e)
                continue

            # Update
            stripes[roothash][C_o.index(sender)] = stripe
            echoSenders.add(sender)
            echoCounter[roothash] += 1

            if echoCounter[roothash] >= EchoThreshold and not readySent:
                readySent = True
                broadcast(('READY', roothash))

            if len(ready[roothash]) >= OutputThreshold and echoCounter[roothash] >= K_o:
                m = decode_output(roothash)
                comms, encryptions, proofs = loads(m)
                return comms, encryptions, proofs

        elif msg[0] == 'READY':
            (_, roothash) = msg
            # Validation
            if sender in ready[roothash] or sender in readySenders:
                print("Redundant READY")
                continue

            # Update
            ready[roothash].add(sender)
            readySenders.add(sender)

            # Amplify ready messages
            if len(ready[roothash]) >= ReadyThreshold and not readySent:
                readySent = True
                broadcast(('READY', roothash))

            if len(ready[roothash]) >= OutputThreshold and echoCounter[roothash] >= K_o:

                m = decode_output(roothash)
                comms, encryptions, proofs = loads(m)
                # print("load", dealer)
                # if predicate(C_n, pid, ePKs, g, comms, encryptions, proofs):
                return comms, encryptions, proofs
                # else:
                #     print("wrong in predicate!")
                #     return -1
                # print(pid, "return in acss")