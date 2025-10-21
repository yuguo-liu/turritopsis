import os
import argparse

def load_all_files(folder_pathes):
    file_contents = []
    
    for filename in folder_pathes: 
        try:
            with open(filename, 'r', encoding='utf-8') as file:
                content = file.readlines()
                file_contents.append(content)
                print(f"loaded file: {filename}")
        except Exception as e:
            print(f"error is occurred when reading {filename}: {e}")
    
    return file_contents

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--P', metavar='P', required=True,
                        help='Protocol (s, t or a)', type=str)
    parser.add_argument('--N', metavar='N', required=True,
                        help='Total number of nodes', type=int)
    parser.add_argument('--n', metavar='n', required=True,
                        help='Number of nodes per switch', type=int)
    parser.add_argument('--r', metavar='r', required=True,
                        help='number of round', type=int)
    parser.add_argument('--s', metavar='s', required=True,
                        help='round per refresh', type=int)
    args = parser.parse_args()
    P = args.P
    N = args.N
    n = args.n
    r = args.r
    s = args.s
    
    if P == "a":
        adkr_files = [f"printOut/adkr-node-{i}.out" for i in range(N)]
        adkr_contents = load_all_files(adkr_files)

        for (i, c) in enumerate(adkr_contents):
            c_last = c[-1]
            if c_last == f"{i} set stop as true\n":
                print(f"\033[32m[Good]\033[0m Find terminated info from node {i}.")
            else:
                print(f"\033[31m[Bad]\033[0m Cannot find the terminated info from node {i}.")
                exit(-1)
        print(f"\033[32m[Pass]\033[0m Consensus protocol is correctly terminated")
        print(f"\033[32m[Pass]\033[0m Liveness of the consensus protocol is verified")


    else:
        num_s = r // s

        log_files = [f"log/consensus-node-{i}.log" for i in range(N)] if P == "s" else [f"log/consensus-node-{i}.log" for i in range(N + num_s * n)]
        con_files = [f"consensus_result/consensus-{i}.cons" for i in range(N)] if P == "s" else [f"consensus_result/consensus-{i}.cons" for i in range(N + num_s * n)]
        log_contents = load_all_files(log_files)
        con_contents = load_all_files(con_files)

        con_contents = [c[:-1] if c[0].startswith("0") else c for c in con_contents]

        expected_num_txs = []
        if P == "s":
            expected_num_txs = [r for _ in range(N)]
        elif P == "t":
            expected_num_txs = [0 for _ in range(N + num_s * n)]
            for i in range(num_s + 1):
                for j in range(i * n, i * n + N):
                    expected_num_txs[j] += s
            
            # print(expected_num_txs)
            flag = False
            diff = 0
            for i in range(len(expected_num_txs)):
                if expected_num_txs[i] > r:
                    diff = expected_num_txs[i] - r
                    expected_num_txs[i] = r
                    flag = True
                elif flag:
                    expected_num_txs[i] -= diff
            
        for (i, c) in enumerate(con_contents):
            if len(c) == expected_num_txs[i]:
                print(f"\033[32m[Good]\033[0m Find {expected_num_txs[i]} txs from node {i}.")
            else:
                print(f"\033[31m[Bad]\033[0m Find insufficient txs from node {i}. (Expected {expected_num_txs[i]}, got {len(c)})")
                exit(-1)
        print(f"\033[32m[Pass]\033[0m Expected number of txs are found.")

        for (i, c) in enumerate(log_contents):
            c_last = c[-1].split(" run INFO ")[-1]
            if c_last == "set stop as true \n":
                print(f"\033[32m[Good]\033[0m Find terminated info from node {i}.")
            else:
                print(f"\033[31m[Bad]\033[0m Cannot find the terminated info from node {i}.")
                exit(-1)
        print(f"\033[32m[Pass]\033[0m Consensus protocol is correctly terminated")
        print(f"\033[32m[Pass]\033[0m Liveness of the consensus protocol is verified")
