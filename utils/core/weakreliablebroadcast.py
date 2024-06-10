# coding=utf-8
import time
from collections import defaultdict

import gevent

import hashlib
import math

import numpy as np


def hash(x):
    assert isinstance(x, (str, bytes))
    try:
        x = x.encode()
    except AttributeError:
        pass
    return hashlib.sha256(x).digest()




def weakreliablebroadcast(sid, pid, N, f, leader, input, output, receive, send, predicate=lambda x: True):
    """weak Reliable broadcast

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
        for i in range(N):
            send(i, o)

    if pid == leader:
        # The leader erasure encodes the input, sending one strip to each participant
        m = input()  # block until an input is received
        # XXX Python 3 related issue, for now let's tolerate both bytes and
        # strings
        # (with Python 2 it used to be: assert type(m) is str)
        assert isinstance(m, (str, bytes))
        # print('Input received: %d bytes' % (len(m),))

        # stripes = encode(K, N, m)
        # mt = merkleTree(stripes)  # full binary tree
        # roothash = mt[1]
        for i in range(N):
            send(i, ('VAL', m))

    # TODO: filter policy: if leader, discard all messages until sending VAL

    fromLeader = None
    stripes = defaultdict(lambda: [None for _ in range(N)])
    echoCounter = defaultdict(lambda: 0)
    echoSenders = set()  # Peers that have sent us ECHO messages
    ready = defaultdict(set)
    m_recv = None
    readySent = False
    readySenders = set()  # Peers that have sent us READY messages
    def wait_for_send_echo(m_recv):
        while True:
            if not predicate(m_recv):
                continue
            broadcast(('ECHO', hash(m_recv)))
            gevent.sleep(0)

    while True:  # main receive loop

        sender, msg = receive()
        if msg[0] == 'VAL' and fromLeader is None:
            # Validation
            (_, m) = msg

            if sender != leader:
                print("VAL message from other than leader:", sender)
                continue
            m_recv = m
            gevent.spawn(wait_for_send_echo, m_recv)
            # broadcast(('ECHO', hash(m)))

        elif msg[0] == 'ECHO':
            (_, h_m) = msg
            # Validation

            echoCounter[h_m] += 1

            if echoCounter[h_m] >= EchoThreshold and not readySent:
                readySent = True
                broadcast(('READY', h_m))

            if len(ready[h_m]) >= OutputThreshold:
                if m_recv:
                    if hash(m_recv) == h_m:
                        return m_recv
                    else:
                        return None
                else:
                    return None


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

            if len(ready[h_m]) >= OutputThreshold:

                if m_recv:
                    if hash(m_recv) == h_m:
                        return output(m_recv)
                    else:
                        return output(None)

                return h_m



