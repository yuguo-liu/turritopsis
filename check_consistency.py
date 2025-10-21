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
    args = parser.parse_args()
    N = args.N

    log_files = [f"consensus_result/consensus-{i}.cons" for i in range(N)]
    contents = load_all_files(log_files)
    
    lens = [len(c) for c in contents]
    max_len = max(lens)
    num_c = len(contents)

    cons_hashes = []
    for c in contents:
        cons_hash = []
        start_idx = 0
        for l in c:
            l_split = l.split("[------]")
            idx, cons_h = l_split[0], l_split[1]
            if len(cons_hash) == 0:
                start_idx = int(idx)
                for _ in range(start_idx):
                    cons_hash.append("deadbeef")
            
            cons_hash.append(cons_h)
            
            if len(cons_hash) == len(c) + start_idx and max_len > len(cons_hash):
                for i in range(len(cons_hash), max_len):
                    cons_hash.append("deadbeef")
        cons_hashes.append(cons_hash)
    
    for i in range(max_len):
        pivot = cons_hashes[0][i]
        for j in range(num_c):
            if pivot == "deadbeef":
                pivot = cons_hashes[j][i]
            elif pivot != cons_hashes[j][i] and cons_hashes[j][i] != "deadbeef":
                print(f"\033[31m[Failed]\033[0m Inconsistency detected in Round {i + 1}!")
                exit(-1)
        if i % 50 == 49:
            print(f"\033[32m[Good]\033[0m Consistency is satisfied in Rounds {i - 48} to {i + 1}")

    print(f"\033[32m[Pass]\033[0m Consistency is satisfied !!!")     
