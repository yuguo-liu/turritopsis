import time
from collections import defaultdict
from utils.core.bls_bn import sign, verify_share, verify_signature, hash_message, combine_shares

from charm.toolbox.pairinggroup import PairingGroup
from utils.core.merkleTree import encode, decode
from utils.core.merkleTree import merkleTree, getMerkleBranch, merkleVerify
from gevent import monkey
from utils.core.serializer import serialize_G2,deseralize_G2
stop = 0


def provabledispersalbroadcast(sid, pid, N, f, PK, SK1, leader, input, output, receive, send):
    """Reliable broadcast

    :param int pid: ``0 <= pid < N``
    :param int N:  at least 3
    :param int f: fault tolerance, ``N >= 3f + 1``
    :param PK1: ``boldyreva.TBLSPublicKey`` with threshold n-f
    :param SK1: ``boldyreva.TBLSPrivateKey`` with threshold n-f
    :param int leader: ``0 <= leader < N``
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
            ``READY( roothash, sigma )``
                sent after receiving :math:`N-f` ``ECHO`` messages
                or after receiving :math:`f+1` ``READY`` messages

    """
    # print("pd start pid:", pid, "leder:",leader)
    assert N >= 3 * f + 1
    assert f >= 0
    assert 0 <= leader < N
    assert 0 <= pid < N

    K = N - 2 * f  # Need this many to reconstruct. (# noqa: E221)
    # EchoThreshold = N - f  # Wait for this many ECHO to send READY. (# noqa: E221)
    # ReadyThreshold = f + 1  # Wait for this many READY to amplify READY. (# noqa: E221)
    SignThreshold = 2 * f + 1  # Wait for this many READY to output

    def broadcast(o):
        send(-1, o)
    digest_leader = None
    digest_leader2 = None
    if pid == leader:
        m = input()
        assert isinstance(m, (str, bytes, list, tuple))
        start = time.time()
        stripes = encode(K, N, m)
        mt = merkleTree(stripes)
        roothash = mt[1]
        digest_leader = hash_message(str(('STORED', sid, roothash)))
        digest_leader2 = hash_message(str(('LOCKED', sid, roothash)))
        for i in range(N):
            branch = getMerkleBranch(i, mt)
            send(i, ('STORE', sid, roothash, stripes[i], branch))
        end = time.time()
        # print("encoding time: " + str(end - start))

    stop = 0
    recstorefromleader = 0
    recstored = [0 for n in range(N)]
    reclockfromleader = 0
    reclocked = [0 for n in range(N)]

    storedSenders = set()  # Peers that have sent us READY messages
    storedSigShares = [None for n in range(N)]
    lockedSenders = set()
    lockedSigShares = [None for n in range(N)]
    LOCKSEND = False
    DONESEND = False
    lock = ()
    store = ()
    while True:
        sender, msg = receive()
        if stop != 0:
            # print("this PD is stopped")
            return 0
        if msg[0] == 'STORE':
            (_, sid, roothash, stripe, branch) = msg
            if sender != leader:
                # print("STORE message from other than leader:", sender)
                continue
            elif recstorefromleader != 0:
                # print("not the first time receive STORE from leader")
                continue
            try:
                # assert stop == 0
                assert merkleVerify(N, stripe, roothash, branch, pid)
            except Exception as e:
                print("Failed to validate STORE message:", e)
                continue
            # UPDATE
            store = (roothash, pid, stripe, branch)
            output(('STORE', store, sid, pid))
            # getStore(store, sid)
            recstorefromleader = 1
            digest1 = hash_message(str(('STORED', sid, roothash)))
            send(leader, ('STORED', sid, serialize_G2(sign(SK1, digest1))))
            if pid != leader and lock:
                return 1
        # receiving STORED message from pi
        elif msg[0] == 'STORED':

            if pid != leader:
                print(pid, " is not a leader in this pd instance")
                continue
            elif recstored[sender] != 0:
                print("not the first time receive STORED from node:", sender)
                continue

            (_, sid, raw_sigma) = msg
            sigma = deseralize_G2(raw_sigma)
            # print(sender, "send ", sigma)

            try:
                assert stop == 0
                # digest = PK1.hash_message(str(('STORED', sid, roothash)))
                # assert PK1.verify_share(sigma, sender, digest_leader)
            except AssertionError:
                # print("Signature share failed in PD!", (sid, pid, sender, msg))
                continue
            # print("receive the stored! from ", sender )
            # UPDATE S1
            recstored[sender] += 1
            # stored[roothash].add(sender)
            storedSenders.add(sender)
            storedSigShares[sender] = sigma

            if len(storedSenders) == SignThreshold and LOCKSEND == False:
                siglist1 = []
                for i in range(N):
                    if storedSigShares[i] != None:
                        siglist1.append((i, storedSigShares[i]))

                sigmas1 = dict(siglist1[:N - f])
                # print(sigmas1)
                Sigma1 = combine_shares(sigmas1)
                assert verify_signature(PK, Sigma1, hash_message(str(('STORED', sid, roothash))))
                # print(Sigma1)

                broadcast(('LOCK', sid, roothash, serialize_G2(Sigma1)))
                LOCKSEND = True

        elif msg[0] == 'LOCK':
            if sender != leader:
                print("LOCK message from other than leader:", sender)
                continue
            elif reclockfromleader != 0:
                print("not the first time receive LOCK from leader")
                continue

            (_, sid, roothash, raw_Sigma1) = msg
            Sigma1 = deseralize_G2(raw_Sigma1)

            try:
                assert stop == 0
                if pid != leader:
                    digest = hash_message(str(('STORED', sid, roothash)))
                    assert verify_signature(PK, Sigma1, digest)
            except Exception as e:
                print("Failed to validate LOCK message:", e)
                continue

            # UPDATE
            lock = (roothash, Sigma1)
            output(('LOCK', lock, sid, pid))
            # getLock(lock, sid, pid)
            reclockfromleader = 1
            digest2 = hash_message(str(('LOCKED', sid, roothash)))
            send(leader, ('LOCKED', sid, serialize_G2(sign(SK1, digest2))))
            if pid != leader and store:
                return 1

        elif msg[0] == 'LOCKED':
            (_, sid, raw_sigma2) = msg
            sigma2 = deseralize_G2(raw_sigma2)
            if pid != leader:
                print(pid, " is not a leader in this pd instance")
                continue
            elif reclocked[sender] != 0:
                print("not the first time receive STORED from node:", sender)
                continue
            try:
                assert stop == 0
                # digest = PK1.hash_message(str(('LOCKED', sid, roothash)))
                # assert PK1.verify_share(sigma2, sender, digest_leader2)
            except AssertionError:
                print("Signature share failed in PD!", (sid, pid, sender, msg))
                continue

            # UPDATE S2
            reclocked[sender] += 1
            # locked[roothash].add(sender)
            lockedSenders.add(sender)
            lockedSigShares[sender] = sigma2

            if len(lockedSenders) == SignThreshold and DONESEND == False:
                siglist2 = []
                for i in range(N):
                    if lockedSigShares[i] != None:
                        siglist2.append((i, lockedSigShares[i]))

                sigmas2 = dict(siglist2[:N - f])
                Sigma2 = combine_shares(sigmas2)
                digest2 = hash_message(str(('LOCKED', sid, roothash)))
                assert verify_signature(PK, Sigma2, digest2)
                done = (roothash, Sigma2)

                output(('DONE', done, sid, pid))
                # getDone(done, sid, pid)
                DONESEND = True
                # print("leader", leader, "is return", done)
                return 1


def abandon(sid):
    stop = 1
