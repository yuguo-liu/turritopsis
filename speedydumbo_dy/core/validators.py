import hashlib, pickle
from crypto.ecdsa.ecdsa import ecdsa_vrfy

def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()

def pb_validate(sid, N, f, l, PK2s, proof):
    try:
        pb_sid, digest, sigmas = proof
        # print(pb_sid, sid)
        if len(sigmas) != N - f - l and len(set(sigmas)) == N - f - l:
            print(len(sigmas), "wrong sig length")
        d = hash((pb_sid, digest))
        for (i, sig_i) in sigmas:
            # print(i)
            if not ecdsa_vrfy(PK2s[i], d, sig_i):
                print("wrong sig")
        return True
    except AssertionError as e:
        print(e)
        return False