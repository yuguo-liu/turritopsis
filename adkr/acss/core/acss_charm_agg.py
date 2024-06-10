# coding=utf-8
import time
from collections import defaultdict
import logging
import os
import gevent
import zfec
import hashlib
import math
from adkr.acss.core.reliablebroadcast import encode, decode, ceil, merkleTree, merkleVerify, getMerkleBranch
from charm.toolbox.ecgroup import ECGroup, G, ZR
from charm.toolbox.pairinggroup import PairingGroup, G1
from pickle import dumps, loads
import phe
from adkr.acss.core.polynomial_charm import polynomials_over
from adkr.acss.core.polynomial_pairing_cp import polynomials_over_BN

def hash(x):
    assert isinstance(x, (str, bytes))
    try:
        x = x.encode()
    except AttributeError:
        pass
    return hashlib.sha256(x).digest()


def completesecretsharing(sid, pid, r, N_o, f_o, l_o, C_o, N_n, f_n, l_n, C_n,  g, type, dealer, PKs, SK, input, receive, send, logger):
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

        where ``tag`` is one of ``{"VAL", "ECHO", "READY"}``
    :param send: sends (without blocking) a message to a designed
        recipient ``send(i, (tag, ...))``

    :return str: ``m`` after receiving :math:`2f+1` ``READY`` messages
        and :math:`N-2f` ``ECHO`` messages

        .. important:: **Messages**

            ``VAL( roothash, branch[i], stripe[i] )``
                sent from ``leader`` to each other party
            ``ECHO( roothash, branch[i], stripe[i] )``
                sent after receiving ``VAL`` message
            ``READY( roothash )``
                sent after receiving :math:`N-f` ``ECHO`` messages
                or after receiving :math:`f+1` ``READY`` messages

    .. todo::
        **Accountability**

        A large computational expense occurs when attempting to
        decode the value from erasure codes, and recomputing to check it
        is formed correctly. By transmitting a signature along with
        ``VAL`` and ``ECHO``, we can ensure that if the value is decoded
        but not necessarily reconstructed, then evidence incriminates
        the leader.

    """
    if type == 's':
        group = ECGroup(714)
    elif type == 'b':
        group = PairingGroup('BN254')
    # assert N >= 3*f + 1
    # assert f >= 0
    # assert 0 <= dealer < N
    # assert 0 <= pid < N
    K_o               = N_o - 2 * f_o - l_o  # Need this many to reconstruct. (# noqa: E221)
    EchoThreshold   = N_o - f_o - l_o      # Wait for this many ECHO to send READY. (# noqa: E221)
    ReadyThreshold  = N_o - 2 * f_o - l_o      # Wait for this many READY to amplify READY. (# noqa: E221)
    OutputThreshold = N_o - f_o - l_o  # Wait for this many READY to output
    # logger.info('node %s starts ss %s' % (pid, dealer))
    # group = PairingGroup('BN256')
    # NOTE: The above thresholds  are chosen to minimize the size
    # of the erasure coding stripes, i.e. to maximize K.
    # The following alternative thresholds are more canonical
    # (e.g., in Bracha '86) and require larger stripes, but must wait
    # for fewer nodes to respond
    #   EchoThreshold = ceil((N + f + 1.)/2)
    #   K = EchoThreshold - f



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
        e = group.hash(dumps([pk, group.serialize(g), group.serialize(Y), c, group.serialize(T)]))
        z = u + int(e) * int(x)
        s = pk.get_random_lt_n()
        e_u = pk.encrypt(u, r_value=s)
        w = (pow(r, int(e), pk.nsquare) * s) % pk.nsquare
        proof = [group.serialize(T), z, e_u, w]
        return [group.serialize(Y), c, proof]

    def verify_knowledge_of_discrete_log(pk, g, Y, c, proof):
        T, z, e_u, w = proof
        e = group.hash(dumps([pk, group.serialize(g), Y, c, T]))
        # be_secure is default true and adds a randomizing factor to the ciphertext as a failsafe.
        # we need it turned off so that the calculations will be correct
        c_e = pow(c, int(e), pk.nsquare)
        return group.deserialize(T) == (g ** z) * (group.deserialize(Y) ** (-e)) and \
               (e_u.ciphertext(be_secure=False) * c_e) % pk.nsquare == pk.encrypt(z, r_value=w).ciphertext(
            be_secure=False)


    def predicate(m):
        comms, encryptions, proofs = loads(m)
        try:
            for i in range(N_n):
                if dealer == pid:
                    continue
                # if dealer == 2: print(PKs[C_n[i]], g, comms[i], encryptions[i], proofs[i])
                if not verify_knowledge_of_discrete_log(PKs[C_n[i]], g, comms[i], encryptions[i], proofs[i]):
                    print(pid, "verify failed", C_n[i], "for dealer", dealer)
                pass
            # share = ZR(SK.raw_decrypt(encryptions[pid]))
            e_time = time.time()
            """
            if dealer==2:
                print(pid, sid, e_time-s_time)
                print(pid, "acss[", sid, "]")
                print(proofs)
                print(encryptions)
                print(comms)
            """
            return comms, encryptions, proofs
        except Exception as e:
            print("Failed to verify acss script:", e)


    def broadcast(o):
        for i in C_o:
            send(i, o)
        # send(-1, o)
    s_time = time.time()
    thpks = []
    if pid == dealer:
        # The leader erasure encodes the input, sending one strip to each participant
        m = input()  # block until an input is received
        # print("dealer", pid, "get acss input", m)
        # logger.info('dealer %s get acss input %d' % (pid, m))
        if type == 's':
            poly = polynomials_over()
        else:
            poly = polynomials_over_BN()
        phi = poly.random(f_n, m)
        # logger.info('dealer %s get poly phi %d' % (pid, phi(0)))
        # if pid == r % 9 or pid == (r+1) % 9:
        #    outputs = [prove_knowledge_of_encrypted_dlog(g, phi(C_n[i] + 1), PKs[C_n[0]]) for i in range(N_n)]
        # else:
        outputs = [prove_knowledge_of_encrypted_dlog(g, phi(C_n[i] + 1), PKs[C_n[i]]) for i in range(N_n)]
        msg = dumps([[outputs[i][j] for i in range(N_n)] for j in range(3)])
        # logger.info('node %s generate ss %s output' % (pid, dealer))
        for i in range(N_n):
            thpks.append([C_n[i] + 1, g ** phi(C_n[i] + 1)])
        if type =='b':
            from adkr.keyrefersh.core.poly_misc_bn import interpolate_g1_at_x
            thpk = interpolate_g1_at_x(thpks[:f_n + 1], 0, group.init(G1))
            assert thpk == g ** m
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

    def decode_output(roothash):
        # Rebuild the merkle tree to guarantee decoding is correct
        m = decode(K_o, N_o, stripes[roothash])
        _stripes = encode(K_o, N_o, m)
        _mt = merkleTree(_stripes)
        _roothash = _mt[1]
        # TODO: Accountability: If this fails, incriminate leader
        assert _roothash == roothash

        return m
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
                # print(pid, "return in acss")
                return comms, encryptions, proofs
