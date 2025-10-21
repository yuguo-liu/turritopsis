from crypto.ecdsa.ecdsa import pki
import pickle
import os
import phe
from g_thresh_gen import generate_thre_new, trusted_nonthre_key_gen
from utils.core.serializer import serialize, deserialize
import argparse

def trusted_key_gen(N, t, N_all):
    keypairs = [phe.paillier.generate_paillier_keypair(n_length=2048) for _ in range(N_all)]
    ePKs1, eSKs1 = [[keypairs[i][j] for i in range(N_all)] for j in range(2)]
    ePKs2, eSKs2 = trusted_nonthre_key_gen(N_all)
    _, _, thpk, thpks, thsks = generate_thre_new(N, 2 * t)
    _, _, thpk2, thpks2, thsks2 = generate_thre_new(N, t)
    sPK2s, sSK2s = pki(N_all)
    # Save all keys to files
    if 'keys' not in os.listdir(os.getcwd()):
        os.mkdir(os.getcwd() + '/keys')


    for i in range(N_all):
        with open(os.getcwd() + '/keys-'+str(N) + '/' + 'ePK1-' + str(i) + '.key', 'wb') as fp:
            pickle.dump(ePKs1[i], fp)

    for i in range(N_all):
        with open(os.getcwd() + '/keys-'+str(N) + '/' + 'eSK1-' + str(i) + '.key', 'wb') as fp:
            pickle.dump(eSKs1[i], fp)


    for i in range(N_all):
        with open(os.getcwd() + '/keys-'+str(N) + '/' + 'ePK2-' + str(i) + '.key', 'wb') as fp:
            pickle.dump(serialize(ePKs2[i]), fp)

    for i in range(N_all):
        with open(os.getcwd() + '/keys-'+str(N) + '/' + 'eSK2-' + str(i) + '.key', 'wb') as fp:
            pickle.dump(eSKs2[i], fp)


    for i in range(N):
        with open(os.getcwd() + '/keys-'+str(N)+'/' + 'thPK1-' + str(i) + '.key', 'wb') as fp:
            pickle.dump(serialize(thpks[i]), fp)


    with open(os.getcwd() + '/keys-'+str(N) + '/' + 'thPK1' + '.key', 'wb') as fp:
            pickle.dump(serialize(thpk), fp)

    for i in range(N):
        with open(os.getcwd() + '/keys-'+str(N) + '/' + 'thSK1-' + str(i) + '.key', 'wb') as fp:
            pickle.dump(thsks[i], fp)


    for i in range(N):
        with open(os.getcwd() + '/keys-'+str(N)+'/' + 'thPK2-' + str(i) + '.key', 'wb') as fp:
            pickle.dump(serialize(thpks2[i]), fp)


    with open(os.getcwd() + '/keys-'+str(N) + '/' + 'thPK2' + '.key', 'wb') as fp:
            pickle.dump(serialize(thpk2), fp)

    for i in range(N):
        with open(os.getcwd() + '/keys-'+str(N) + '/' + 'thSK2-' + str(i) + '.key', 'wb') as fp:
            pickle.dump(thsks2[i], fp)

    # public keys of ECDSA
    for i in range(N_all):
        with open(os.getcwd() + '/keys-'+str(N) + '/' + 'sPK2-' + str(i) + '.key', 'wb') as fp:
            pickle.dump(sPK2s[i].format(), fp)
    # private keys of ECDSA
    for i in range(N_all):
        with open(os.getcwd() + '/keys-'+str(N) + '/' + 'sSK2-' + str(i) + '.key', 'wb') as fp:
            pickle.dump(sSK2s[i].secret, fp)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--N', metavar='N', required=True,
                        help='Total number of party', type=int)
    parser.add_argument('--Ng', metavar='Ng', required=True,
                        help='Number of party in one round', type=int)
    parser.add_argument('--f', metavar='f',required=True,
                        help='Number of Byzantine Fault party', type=int)
    parser.add_argument('--l', metavar='l', required=True,
                        help='Number of in/out party in each refresh', type=int)
    parser.add_argument('--r', metavar='r', required=True,
                        help='Number of round', type=int)
    parser.add_argument('--rf', metavar='rf', required=True,
                        help='Refresh Frequency', type=int)
    args = parser.parse_args()

    N = args.N
    Ng = args.Ng
    f = args.f
    l = args.l
    r = args.r
    rf = args.rf

    assert Ng >= 3*f + 2*l + 1, f'Following relation should be held: \n N >= 3f + 2l + 1\nYour input:\n {Ng} < 3x{f} + 2x{l} + 1 = {3*f + 2*l + 1}'
    assert N >= Ng + l * (r // rf), f'Following relation should be held: \n N >= Ng + l * (r // rf)\nYour input:\n {N} < {Ng} + {l} * ({r} // {rf}) = {Ng + l * (r // rf)}'
    
    print(N, Ng, f, l, r, rf)

    if f'keys-{Ng}' not in os.listdir(os.getcwd()):
        os.mkdir(os.getcwd() + f'/keys-{Ng}')
        
    trusted_key_gen(Ng, f, N)
