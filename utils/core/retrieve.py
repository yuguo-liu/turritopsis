# new rc
import hashlib
import pickle
import time
from collections import defaultdict

import gevent
from gevent import monkey
from crypto.threshsig.boldyreva import serialize, deserialize1
from utils.core.merkleTree import encode, decode
from utils.core.merkleTree import merkleTree, getMerkleBranch, merkleVerify
import traceback

def retrieve(pid, sid, N, f,  getchunk, receive, send):

    assert N >= 3 * f + 1
    assert f >= 0
    assert 0 <= pid < N
    K = f + 1

    returnchunksend = False
    rcstorerec = [0 for n in range(N)]
    stripes = defaultdict(lambda: [None for _ in range(N)])
    branchs = defaultdict(lambda: [None for _ in range(N)])
    # commit = defaultdict(set)
    r_counter = defaultdict(lambda: 0)
    def hash(x):
        return hashlib.sha256(pickle.dumps(x)).digest()

    def broadcast(o):
        print("send")
        send(-1, o)

    def getinput():
        nonlocal returnchunksend

        while True:
            gevent.sleep(0)
            try:
                chunk = getchunk()
                (stripe, branch, roothash) = chunk
                if not returnchunksend and stripe != 0:
                    print(pid, "get and send")
                    broadcast(('RETURNCHUNK', chunk))
                    returnchunksend = True

                break
            except Exception as e:
                traceback.print_exc(e)
                continue

    gevent.spawn(getinput)

    while True:
        gevent.sleep(0)
        sender, msg = receive()

        if msg[0] == 'RETURNCHUNK':
            (_, chunk) = msg
            (stripe, branch, roothash) = chunk
            try:
                assert merkleVerify(N, stripe, roothash, branch, sender)
            except Exception as e:
                print("Failed to validate returnchunk message from:", sender, e)
                continue
            stripes[roothash][sender] = stripe
            branchs[roothash][sender] = branch
            r_counter[roothash] +=1
            if r_counter[roothash] >= f + 1:
                # print(pid, sid, "f+1")
                v = decode(K, N, stripes[roothash])
                if merkleTree(encode(K, N, v))[1] == roothash:
                    # print("now print v:", bytes.decode(v))
                    # print(pid, "return rc", sid)
                    return bytes.decode(v)
                else:
                    return 0

