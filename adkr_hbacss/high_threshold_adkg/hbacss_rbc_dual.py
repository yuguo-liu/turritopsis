# coding=utf-8
from collections import defaultdict
import os
import gevent
from gevent import monkey
import hashlib
import math
from utils.core.betterpairing import G1, ZR
from pickle import dumps, loads
import phe
from adkr.acss.core.polynomial_pairing import polynomials_over_BN as polynomials_over_BN_N
from utils.core.serializer import serialize, deserialize
import traceback, time
from utils.core.bls_bn import sign, verify_share, verify_signature, hash_message, combine_shares
from adkr.keyrefersh.core.poly_misc_bn import interpolate_at_x1, interpolate_g1_at_x
from adkr_hbacss.high_threshold_adkg.AES  import AESCipher
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


def completesecretsharing(sid, pid, N_o, f_o, C_o, N_n, f_n, C_n, g, h, dealer,  ePKs, eSK,  input, output, receive, send, logger):
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

    K               = N_o - 2 * f_o  # Need this many to reconstruct. (# noqa: E221)
    EchoThreshold   = N_o - f_o      # Wait for this many ECHO to send READY. (# noqa: E221)
    ReadyThreshold  = f_o + 1      # Wait for this many READY to amplify READY. (# noqa: E221)
    OutputThreshold = 2 * f_o + 1



    logger.info('%s, start' % sid)

    def broadcast(o):
        # for i in C_o:
        #     send(i, o)
        send(-1, o)

    def Ped_Verify(g, h, commit, i, si, ri, f):
        res = G1.identity()
        for j in range(f + 1):
            res *= deserialize(commit[j]) ** ((i + 1) ** j)
        # print(res)
        # print((g ** si) * (h ** ri))
        return res == (g ** si) * (h ** ri)

    def Verify_and_decrypt(g, h, pid, commit, script_i, script2_i, t):
        gs = []
        kdi = ePKs[dealer] ** eSK
        si = AESCipher(str(kdi)).decrypt(script_i)
        ri = AESCipher(str(kdi)).decrypt(script2_i)
        # ri = ciphers[pid].decrypt(c2)
        # share = group.init(ZR, int(si))
        # random = group.init(ZR, int(ri))
        share = ZR(si)
        share_r = ZR(ri)
        # random = ZR(ri)
        # print("it is", share)
        # Verify_proof(g1, PKs[pid], pkd, c, z, kds[pid])
        s1 = time.time()
        # assert check_degree(t, commit)
        # assert g1 ** share == commit[pid]
        if Ped_Verify(g, h, commit, pid, share, share_r, t):
            # print("===", time.time() - s1)
            return (si, ri)
        else:
            return False

    def predicate(m):
        s1, s2, coms, sb1, sb2, comsb, dealer = loads(m)
        r = Verify_and_decrypt(g, h, pid, coms, s1[pid], s2[pid], f_n)
        rb = Verify_and_decrypt(g, h, pid, comsb, sb1[pid], sb2[pid], f_n)
        return (r, rb, coms, comsb)

    s_time = time.time()
    kds = []
    ciphers = []
    for i in range(N_o):
        kds.append(ePKs[i] ** eSK)
        ciphers.append(AESCipher(str(kds[i])))

    def deal(f, m, ciphers):
        script = []
        script2 = []
        poly = polynomials_over_BN_N(ZR)
        r = ZR.rand()
        phi = poly.random(f, m)
        phi2 = poly.random(f, r)
        commits = []
        # commit0 = (g ** phi.coeffs[0])*(g2 ** phi.coeffs[0])
        for i in range(f + 1):
            commits.append(serialize((g ** phi.coeffs[i]) * (h ** phi2.coeffs[i])))
        for i in range(N_n):
            c1 = ciphers[i].encrypt(str(phi(i + 1)))
            c2 = ciphers[i].encrypt(str(phi2(i + 1)))
            # c2 = ciphers[i].encrypt(str(phi2(i + 1)))
            # kdi, c, z = generate_enc(g, PKs[i], SK)
            script.append(c1)
            script2.append(c2)

        return script, script2, commits

    if pid == dealer:
        # The leader erasure encodes the input, sending one strip to each participant
        m = input()  # block until an input is received
        a, b = m
        # logger.info('dealer %s get acss input %d' % (pid, m))
        script, script2, commits = deal(f_n, a, ciphers)
        script_b, script2_b, commits_b = deal(f_n, b, ciphers)
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
        msg = dumps((script, script2, commits, script_b, script2_b, commits_b, dealer))
        # print("dealer", dealer, "gen!", msg)
        # logger.info('node %s generate ss %s output' % (pid, dealer))
        # assert isinstance(msg, (str, bytes, list, tuple))
        stripes = encode(K, N_o, msg)
        mt = merkleTree(stripes)  # full binary tree
        roothash = mt[1]

        for i in range(N_o):
            branch = getMerkleBranch(i, mt)
            send(i, ('VAL', roothash, branch, stripes[i]))

        logger.info('dealer sen val')
    fromLeader = None
    stripes = defaultdict(lambda: [None for _ in range(N_o)])
    echoCounter = defaultdict(lambda: 0)
    echoSenders = set()  # Peers that have sent us ECHO messages
    ready = defaultdict(set)
    m_recv = None
    s_recv = None
    readySent = False
    ADDSent = False
    readySenders = set()  # Peers that have sent us READY messages
    disperse_recv = defaultdict(lambda: 0)
    m_start = None
    rec_set = defaultdict()
    def decode_output(roothash):
        # Rebuild the merkle tree to guarantee decoding is correct
        m = decode(K, N_o, stripes[roothash])
        _stripes = encode(K, N_o, m)
        _mt = merkleTree(_stripes)
        _roothash = _mt[1]

        # TODO: Accountability: If this fails, incriminate leader
        assert _roothash == roothash
        res = predicate(m)
        return res

    while True:  # main receive loop

        sender, msg = receive()
        if msg[0] == 'VAL' and fromLeader is None:
            # Validation
            (_, roothash, branch, stripe) = msg
            if sender != dealer:
                print("VAL message from other than leader:", sender)
                continue
            try:
                assert merkleVerify(N_o, stripe, roothash, branch, pid)
            except Exception as e:
                print("Failed to validate VAL message:", e)
                continue

            # Update
            fromLeader = roothash
            broadcast(('ECHO', roothash, branch, stripe))

        elif msg[0] == 'ECHO':
            (_, roothash, branch, stripe) = msg
            # Validation
            if roothash in stripes and stripes[roothash][sender] is not None \
                    or sender in echoSenders:
                print("Redundant ECHO")
                continue
            try:
                assert merkleVerify(N_o, stripe, roothash, branch, sender)
            except AssertionError as e:
                print("Failed to validate ECHO message:", e)
                continue

            # Update
            stripes[roothash][sender] = stripe
            echoSenders.add(sender)
            echoCounter[roothash] += 1

            if echoCounter[roothash] >= EchoThreshold and not readySent:
                readySent = True
                broadcast(('READY', roothash))
            # print("send ready", sid)
            if len(ready[roothash]) >= OutputThreshold and echoCounter[roothash] >= K:
                output(decode_output(roothash))
                return 1

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

            if len(ready[roothash]) >= OutputThreshold and echoCounter[roothash] >= K:
                output(decode_output(roothash))
                return 1