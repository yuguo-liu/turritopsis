from utils.core.betterpairing import G2, G1, ZR
from utils.core.serializer import serialize
from pickle import dumps, loads

# g ** w = h
def proof_of_knowledge(g, h, w):
    r = ZR.rand()
    a = g ** r
    c = ZR.hash(dumps([serialize(g), serialize(a)]))
    z = r + c * w
    return c, z

def pok_Verify(h, g, proof):
    c, z = proof
    a = (g ** z)/(h ** c)
    assert c == ZR.hash(dumps([serialize(g), serialize(a)]))
    return True

