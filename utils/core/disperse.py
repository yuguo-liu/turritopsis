import time
from queue import Queue

from gevent import monkey;

from honeybadgerbft.core.reliablebroadcast import encode, merkleTree, getMerkleBranch, merkleVerify

monkey.patch_all(thread=False)

from datetime import datetime
from collections import defaultdict
from crypto.ecdsa.ecdsa import ecdsa_vrfy, ecdsa_sign
import hashlib, pickle
from utils.core.merkleTree import encode, decode
from utils.core.merkleTree import merkleTree, getMerkleBranch, merkleVerify



def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()


def disperse(sid, pid, N, f, leader, input, receive, send, logger=None):
    """Consistent broadcast
    :param str sid: session identifier
    :param int pid: ``0 <= pid < N``
    :param int N:  at least 3
    :param int f: fault tolerance, ``N >= 3f + 1``
    :param list PK2s: an array of ``coincurve.PublicKey'', i.e., N public keys of ECDSA for all parties
    :param PublicKey SK2: ``coincurve.PrivateKey'', i.e., secret key of ECDSA
    :param int leader: ``0 <= leader < N``
    :param input: if ``pid == leader``, then :func:`input()` is called
        to wait for the input value
    :param receive: :func:`receive()` blocks until a message is
        received; message is of the form::

            (i, (tag, ...)) = receive()

        where ``tag`` is one of ``{"VAL", "ECHO", "READY"}``
    :param send: sends (without blocking) a message to a designed
        recipient ``send(i, (tag, ...))``

    :return str: ``m`` after receiving ``CBC-FINAL`` message
        from the leader

        .. important:: **Messages**

            ``CBC_VAL( m )``
                sent from ``leader`` to each other party
            ``CBC_ECHO( m, sigma )``
                sent to leader after receiving ``CBC-VAL`` message
            ``CBC_FINAL( m, Sigma )``
                sent from ``leader`` after receiving :math:``N-f`` ``CBC_ECHO`` messages
                where Sigma is computed over {sigma_i} in these ``CBC_ECHO`` messages
    """

    # assert N >= 3*f + 1
    # assert f >= 0
    # assert 0 <= leader < N
    # assert 0 <= pid < N
    st =time.time()
    K = N - 2 * f  # Need this many to reconstruct. (# noqa: E221)
    EchoThreshold = N - f  # Wait for this many ECHO to send READY. (# noqa: E221)
    ReadyThreshold = f + 1  # Wait for this many READY to amplify READY. (# noqa: E221)
    OutputThreshold = 2 * f + 1  # Wait for this many READY to output    m = None
    fromLeader = None
    MyProof = None
    MyChunk = None

    fromLeader = None

    echoCounter = defaultdict(lambda: 0)

    ready = defaultdict(set)
    readySent = False
    # print(sid, "PCBC starts...")
    def broadcast(o):
        #for i in range(N):
        #    send(i, o)
        send(-1, o)

    def decode_output(roothash):
        # Rebuild the merkle tree to guarantee decoding is correct
        if fromLeader == roothash:
            return MyChunk, MyProof, fromLeader
        else:
            return 0, 0, roothash

    if pid == leader:
        m = input()  # block until an input is received

        assert isinstance(m, (str, bytes, list, tuple))
        stripes = encode(K, N, m)
        mt = merkleTree(stripes)  # full binary tree
        roothash = mt[1]
        for i in range(N):
            branch = getMerkleBranch(i, mt)
            send(i, ('AVID_CHUNK', roothash, branch, stripes[i]))
        # print("Leader %d broadcasts CBC SEND messages" % leader)

    # Handle all consensus messages
    while True:
        # gevent.sleep(0)

        (j, msg) = receive()
        # if pid ==3 : print("recv3", (j, msg[0]))

        if msg[0] == 'AVID_CHUNK' and fromLeader is None:
            # CBC_SEND message
            (_, roothash, branch, stripe) = msg
            if j != leader:
                # print("Node %d receives a CBC_SEND message from node %d other than leader %d" % (pid, j, leader), msg)
                continue
            try:
                assert merkleVerify(N, stripe, roothash, branch, pid)
            except Exception as e:
                print("Failed to validate VAL message:", e)
                continue
            # Update
            fromLeader = roothash
            MyProof = branch
            MyChunk = stripe
            # if pid == 3: print("get chunk of", sid, "at ", time.time())
            broadcast(('AVID_ECHO', fromLeader))

        elif msg[0] == 'AVID_ECHO':
            (_, h_r) = msg
            # Validation

            echoCounter[h_r] += 1

            if echoCounter[h_r] >= EchoThreshold and not readySent:
                readySent = True
                broadcast(('AVID_READY', h_r))


        elif msg[0] == 'AVID_READY':
            (_, h_r) = msg
            # Validation
            if j in ready[h_r] or j in ready[h_r]:
                print("Redundant READY")
                continue

            # Update
            ready[h_r].add(j)

            # Amplify ready messages
            if len(ready[h_r]) >= ReadyThreshold and not readySent:
                readySent = True
                broadcast(('AVID_READY', h_r))

            if len(ready[h_r]) >= OutputThreshold:
                return decode_output(h_r)


