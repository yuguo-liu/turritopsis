from myexperiements.localtests.my_run_smvba_dy_malicious import test_smvba
from myexperiements.localtests.my_run_spbc_malicious import test_spbc

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--m', metavar='module', required=True,
                        help='tested module (smvba/spbc)', type=str)
    parser.add_argument('--n', metavar='#party', required=True,
                        help='number of parties', type=int)
    parser.add_argument('--f', metavar='#byzantine', required=True,
                        help='number of byzantine parties', type=int)
    parser.add_argument('--r', metavar='#round', required=False,
                        help='number of tested round', type=int, default=1)

    args = parser.parse_args()
    m = args.m
    n = args.n
    f = args.f
    r = args.r

    if m == 'smvba':
        print("++++++++++ Testing smvba ++++++++++")
        test_smvba(n, f, None, r)
    elif m == 'spbc':
        print("++++++++++ Testing spbc  ++++++++++")
        test_spbc(n, f, None)
    else:
        print("abort")