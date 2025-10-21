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
    parser.add_argument('--N', metavar='N', required=True,
                        help='Total number of nodes', type=int)
    parser.add_argument('--Ng', metavar='Ng', required=True,
                        help='Number of nodes in one round of consensus', type=int)
    parser.add_argument('--l', metavar='l', required=True,
                        help='Number of nodes in one switch', type=int)
    parser.add_argument('--r', metavar='r', required=True,
                        help='Number of rounds', type=int)
    parser.add_argument('--recon', metavar='recon', required=True,
                        help='Reconfiguration frequency', type=int)
    args = parser.parse_args()
    
    N       = args.N
    Ng      = args.Ng
    l       = args.l
    r       = args.r
    recon   = args.recon

    num_s   = r // recon

    # load the consensus result in `contents`
    log_files = [f"consensus_result/consensus-{i}.cons" for i in range(N)]
    contents = load_all_files(log_files)
    
    # parse the contents into rounds and check the continuity
    rounds_list = []
    for (idx, c) in enumerate(contents):
        rounds = [int(x.split("[------]")[0]) for x in c]

        pivot = rounds[0]
        for rou in rounds[1:]:
            if rou - pivot != 1:
                print(f"\033[31m[Failed]\033[0m Continuity Failed in Node {idx}!")
                exit(-1)
            else:
                pivot = rou

        rounds_list.append(rounds)
    
    # check the correctness of dynamic switch in and out
    expected_num_rounds = [[] for _ in range(N)]
    for i in range(num_s + 1):
        for j in range(i * l, i * l + Ng):
            if len(expected_num_rounds[j]) == 0:
                expected_num_rounds[j].append(i * recon + 1)
                expected_num_rounds[j].append(min((i + 1) * recon, r))
            else:
                expected_num_rounds[j][-1] = min((i + 1) * recon, r)
    
    print(expected_num_rounds)
    
    count = 0
    for idx, (rounds, enr) in enumerate(zip(rounds_list, expected_num_rounds)):
        print(f"\033[33m[Info]\033[0m Node {idx} is supposed to run in round {enr[0]} - {enr[1]}", end="")
        if enr[0] > 1:
            print(f", and swap in after    round {enr[0]}")
        elif enr[1] < r:
            print(f", and swap out after    round {enr[1]}")
        else:
            print("")
        
        print(f"\033[33m[Info]\033[0m Node {idx} actually ran in       round {rounds[0]} - {rounds[-1]}", end="")
        if rounds[0] > 1:
            print(f", and swapped in after round {rounds[0]}")
        elif rounds[-1] < r:
            print(f", and swapped out after round {rounds[-1]}")
        else:
            print("")
        
        if enr[0] == rounds[0] and enr[1] == rounds[-1]:
            print(f"\033[32m[Good]\033[0m Node {idx} is correct")
            count += 1
        else:
            print(f"\033[31m[Bad]\033[0m Node {idx} is not correct")
    
    if count == N:
        print(f"\033[32m[Pass]\033[0m All nodes pass ({count} passed / {N})")
    else:
        print(f"\033[31m[Error]\033[0m Some nodes failed ({count} passed / {N})")