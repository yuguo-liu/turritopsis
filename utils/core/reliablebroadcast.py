# coding=utf-8
import time
from collections import defaultdict

import gevent
import reedsolo
import zfec
import hashlib
import math
from reedsolo import RSCodec, ReedSolomonError
import numpy as np
from pickle import dumps, loads

# NOTE: This is not very optimized as it is never triggered in the normal case operation
def encode(k, n, m):
    """encodes string ``m`` into ``n`` blocks, such that any ``k``
    can reconstruct.
    :param int k: k
    :param int n: number of blocks to encode string ``m`` into.
    :param bytes m: bytestring to encode.
    :return list: Return encoding of ``m`` into
        ``n`` blocks using ``reedsolo`` lib.
    """
    rsc = RSCodec(n - k)
    padlen = k - (len(m) % k)
    m += padlen * chr(k - padlen).encode()
    mlen = len(m) // k
    blocks = [m[i * k: (i + 1) * k] for i in range(mlen)]

    stripes = [None] * mlen
    for i in range(mlen):
        stripes[i] = rsc.encode(blocks[i])

    nstripes = np.array(stripes)
    return nstripes.T


# NOTE: This is not very optimized as it is never triggered in the normal case operation
def decode(k, n, stripes):
    """Decodes an error corrected encoded string from a subset of stripes
    :param list stripes: a container of :math:`n` elements,
        each of which is either a string or ``None``
        at least :math:`k` elements are strings
        all string elements are the same length
    """
    rsc = RSCodec(n - k)
    elen = len(list(stripes.values())[0])

    erasure_pos = []
    columns = []

    for i in range(n):
        if i in stripes:
            columns.append(stripes[i])
        else:
            zeros = np.array([0] * elen)
            columns.append(zeros)
            erasure_pos.append(i)

    code_words = np.array(columns).T
    message = []
    try:
        for val in code_words:
            message.append(rsc.decode(list(val))[0])
    except Exception:
        # print("Too many (or few) errors")
        return False
    m = list(np.array(message).flatten())
    padlen = k - m[-1]
    m = m[:-padlen]

    return bytes(m)

def hash(x):
    assert isinstance(x, (str, bytes))
    try:
        x = x.encode()
    except AttributeError:
        pass
    return hashlib.sha256(x).digest()




def reliablebroadcast(sid, pid, N, f, leader, input, receive, send, predicate=lambda x: True, logger=None):
    """Reliable broadcast

    :param int pid: ``0 <= pid < N``
    :param int N:  at least 3
    :param int f: fault tolerance, ``N >= 3f + 1``
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
    assert N >= 3*f + 1
    assert f >= 0
    assert 0 <= leader < N
    assert 0 <= pid < N

    K               = N - 2 * f  # Need this many to reconstruct. (# noqa: E221)
    EchoThreshold   = N - f      # Wait for this many ECHO to send READY. (# noqa: E221)
    ReadyThreshold  = f + 1      # Wait for this many READY to amplify READY. (# noqa: E221)
    OutputThreshold = 2 * f + 1  # Wait for this many READY to output
    # NOTE: The above thresholds  are chosen to minimize the size
    # of the erasure coding stripes, i.e. to maximize K.
    # The following alternative thresholds are more canonical
    # (e.g., in Bracha '86) and require larger stripes, but must wait
    # for fewer nodes to respond
    #   EchoThreshold = ceil((N + f + 1.)/2)
    #   K = EchoThreshold - f

    def broadcast(o):
        send(-1, o)

    if pid == leader:

        # The leader erasure encodes the input, sending one strip to each participant
        m = input()  # block until an input is received
        # XXX Python 3 related issue, for now let's tolerate both bytes and
        # strings
        # (with Python 2 it used to be: assert type(m) is str)
        try:
            assert isinstance(m, (str, bytes))
        except:
            m = dumps(m)
        # print('Input received: %d bytes' % (len(m),))

        # stripes = encode(K, N, m)
        # mt = merkleTree(stripes)  # full binary tree
        # roothash = mt[1]
        send(-1, ('VAL', m))


    t_s = time.time()
    # TODO: filter policy: if leader, discard all messages until sending VAL

    fromLeader = None
    stripes = defaultdict(lambda: [None for _ in range(N)])
    echoCounter = defaultdict(lambda: 0)
    echoSenders = set()  # Peers that have sent us ECHO messages
    ready = defaultdict(set)
    m_recv = None
    readySent = False
    ADDSent = False
    readySenders = set()  # Peers that have sent us READY messages
    disperse_recv = defaultdict(lambda: 0)
    m_start = None
    rec_set = defaultdict()

    while True:  # main receive loop

        sender, msg = receive()
        if msg[0] == 'VAL' and fromLeader is None:
            # Validation
            (_, m) = msg
            if sender != leader:
                print("VAL message from other than leader:", sender)
                continue
            if not predicate(loads(m)):
                print("VAL message does not pass the predicate")
                continue
            m_recv = m
            broadcast(('ECHO', hash(m)))
            if logger:
                logger.info('send echo for %s in %f' %(sid, time.time()-t_s))


        elif msg[0] == 'ECHO':
            (_, h_m) = msg
            # Validation

            echoCounter[h_m] += 1

            if echoCounter[h_m] >= EchoThreshold and not readySent:
                readySent = True
                broadcast(('READY', h_m))
                if logger:
                    logger.info('send ready for %s in %f' % (sid, time.time() - t_s))
            if len(ready[h_m]) >= OutputThreshold and echoCounter[h_m] >= K and not ADDSent:
                ADDSent = True
                if m_recv:
                    stripes = encode(f+1, N, m_recv)
                    for i in range(N):
                        send(i, ('DISPERSE', stripes[i]))
                        m_start = stripes[pid]
                        broadcast(('REC', m_start))

                        return loads(m_start)


        elif msg[0] == 'READY':
            (_, h_m) = msg
            # Validation
            if sender in ready[h_m] or sender in readySenders:
                print("Redundant READY")
                continue

            # Update
            ready[h_m].add(sender)
            readySenders.add(sender)

            # Amplify ready messages
            if len(ready[h_m]) >= ReadyThreshold and not readySent:
                readySent = True
                broadcast(('READY', h_m))

            if len(ready[h_m]) >= OutputThreshold and echoCounter[h_m] >= K and not ADDSent:
                ADDSent = True
                if m_recv:
                    stripes = encode(f+1, N, m_recv)
                    for i in range(N):
                        send(i, ('DISPERSE', stripes[i]))
                    if logger:
                        logger.info('send dis for %s in %f' % (sid, time.time() - t_s))
                    m_start = stripes[pid]
                    broadcast(('REC', t_s))
                    if logger:
                        logger.info('send rec for %s in %f' % (sid, time.time() - t_s))

                    return loads(m_recv)

        elif msg[0] == 'DISPERSE' and not m_recv:
            _, mi = msg
            disperse_recv[str(mi)] += 1
            if disperse_recv[str(mi)] == f + 1:
                m_start = mi
                broadcast(('REC', m_start))


        elif msg[0] == 'REC' and not m_recv:
            _, mj = msg
            rec_set[sender] = mj
            if len(rec_set) >= 2 * f + 1:
                result = decode(f+1, N, rec_set)
                if not result:
                    continue
                else:
                    return loads(result)
