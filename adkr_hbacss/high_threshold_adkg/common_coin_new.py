from gevent import monkey; monkey.patch_all(thread=False)

import logging
from collections import defaultdict
from gevent import Greenlet
from gevent.queue import Queue
import hashlib
from utils.core.betterpairing import G2, G1, ZR
from adkr.keyrefersh.core.poly_misc_bn import interpolate_g1_at_x
from pickle import dumps, loads
from utils.core.serializer import serialize, deserialize
import traceback
logger = logging.getLogger(__name__)


class CommonCoinFailureException(Exception):
    """Raised for common coin failures."""
    pass


def hash(x):
    return hashlib.sha256(x).digest()

def shared_coin(sid, pid, N, f, l, C, g1, receive, broadcast,  single_bit=False, logger=None):
    """A shared coin based on threshold signatures

    :param sid: a unique instance id
    :param pid: my id number
    :param N: number of parties
    :param f: fault tolerance, :math:`f+1` shares needed to get the coin
    :param PK: ``th-PublicKey``
    :param SK: ``th-PrivateKey``
    :param broadcast: broadcast channel
    :param receive: receive channel
    :param single_bit: is the output coin a single bit or not ?
    :return: a function ``getCoin()``, where ``getCoin(r)`` blocks
    """
    received = defaultdict(dict)
    coinshare = defaultdict(lambda: list())
    coin_inter = defaultdict(lambda: list())
    outputQueue = defaultdict(lambda: Queue(1))
    pk_recv = defaultdict(lambda: list())
    gen = defaultdict(lambda: False)
    PKs = None

    def generage_proof(g, pk, sk, v):


        g_e = G1.hash(dumps(int(v)))
        # g_e = G1.hash(dumps(C))
        # print(g_e)
        g_i_e = g_e ** sk
        s = ZR.rand()
        # s = ZR.rand()
        h = g ** s
        h_e = g_e ** s
        c = ZR.hash(dumps([g, pk, h, g_e,g_i_e,h_e]))
        # c = ZR.hash(dumps([g, pk, h, g_e, g_i_e, h_e]))
        z = s + int(sk) * int(c)
        # if pid == 0: print("", z)
        return g_i_e, c, z

    def Verify_proof(g, pk, v, c, z, g_i_e):
        g_e = G1.hash(dumps(v))
        h = (g ** z) / (pk ** c)

        h_e = (g_e ** z) / (g_i_e ** c)
        # assert c == ZR.hash(dumps([g, pk, h, g_e, g_i_e, h_e]))
        try:
            assert c == ZR.hash(dumps([g, pk, h, g_e, g_i_e, h_e]))
            # assert c == group.hash(dumps([group.serialize(g), group.serialize(pk), group.serialize(h),
            #                           group.serialize(g_e), group.serialize(g_i_e), group.serialize(h_e)]), ZR)
            # assert h == (g ** z) / (pk ** c)
        except Exception as e:
            traceback.print_exc(e)
        return True

    def _recv():
        while True:     # main receive loop
            sender, msg = receive()
            # print(sender, msg)
            (_, r, pks, (g_i_e_r, c, z)) = msg
            pk_recv[dumps(pks)].append(sender)
            if len(pk_recv[dumps(pks)]) == f+1:
                PKs = pks
            g_i_e = deserialize(g_i_e_r)
            # print('recv', sender, g_i_e, c, z)
            # g_i_e = group.deserialize(g_i_e_r)
            # c = group.deserialize(c_r)
            # z = group.deserialize(z_r)
            # try:
                # continue
            #     Verify_proof(g1, PKs[sender], r, c, z, g_i_e)
            # except Exception as e:
            #     print("Failed to validate coin message:", e)
            #     traceback.print_exc(e)
            #     continue
            # New shares for some round r, from sender

            # sig = group.deserialize(raw_sig)


            # TODO: Accountability: Optimistically skip verifying
            # each share, knowing evidence available later
            # assert verify_share(PKS[i], sig, h)
            # received[r][sender] = sig

            coinshare[r].append([sender+1, r, c, z, g_i_e])
            # print(pid, r, coinshare[r])
            # After reaching the threshold, compute the output and
            # make it available locally
            if len(coinshare[r]) >= f + 1 and PKs and not gen[r]:
                # Verify and get the combined signature
                # sigs = dict(list(received[r].items())[:f+1])
                # sig = combine_shares(sigs)
                for item in coinshare[r]:
                    sp1, r, c, z, g_i_e = item
                    try:
                        # continue
                        assert Verify_proof(g1, PKs[sp1-1], r, c, z, g_i_e)
                        coin_inter[r].append([sp1, g_i_e])
                    except Exception as e:
                        print("Failed to validate coin message:", e)
                        traceback.print_exc(e)
                        continue
                coin = interpolate_g1_at_x(coin_inter[r], 0, G1.identity())
                coin_int = int.from_bytes(hash(serialize(coin)), byteorder='big')
                # print(pid, "the coin value in view = ", coin_int % N, coin_int)
                gen[r] = True
                if single_bit:
                    bit = coin_int % 2
                    print(sid+str(r), pid, "the coin value =", bit)
                    outputQueue[r].put_nowait(bit)
                else:
                    outputQueue[r].put_nowait(coin_int)

    #greenletPacker(Greenlet(_recv), 'shared_coin', (pid, N, f, broadcast, receive)).start()
    Greenlet(_recv).start()

    def getCoin(round):
        """Gets a coin.

        :param round: the epoch/round.
        :returns: a coin.

        """

        # I have to do mapping to 1..l
        # g_i_e_r, c_r, z_r = (generage_proof(g1, PKs[C.index(pid)], SK, round))
        broadcast(('COIN', round))
        # print(pid, SK)
        coinSender = set()
        coinshare = []
        # h.initPP()
        # print('debug', pid, SK.sign(h), h)
        # print('debug-SK', pid, SK.SK, SK.l, SK.k, SK.i)
        # print('debug-PK', pid, PK.VKs[pid], PK.l, PK.k, PK.VK)
        # print('debug', pid, type(SK.sign(h)), type(h), type(SK.SK), type(PK.VKs[pid]))
        # print('debug', pid, ismember(SK.sign(h)), ismember(h), ismember(SK.SK), ismember(PK.VKs[pid]))

        # assert verify_share(PKS[pid], sig, h)
        # print('OK!')

        coin = outputQueue[round].get()
        # print('debug', 'node %d gets a coin %d for round %d in %s' % (pid, coin, round, sid)
        return coin

    return getCoin
