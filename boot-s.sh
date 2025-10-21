#!bin/bash

# usage: bash boot.sh <N> <Ng> <F> <L> <B> <R> <m> <Rf>
# descriptions
# N : Nodes -- the total number of nodes (N = Ng + (R // Rf) * L)
# Ng: Nodes in a game -- the number of nodes participating in the consensus
# F : Faults -- the number of Byzantine Fault nodes
# L : Leaving -- the number of switching nodes
# B : Batch -- the batch size of tx per round
# R : Rounds -- the number of rounds
# m : Malicious -- the malicious behavior: 0 - close, > 0 - open
# Rf: Refresh frequency -- the frequency of key fresh

# deleta the old logs
cd log
rm consensus-node-*
cd ..

cd parse_log
rm result-sdumbo.json
cd ..

cd consensus_result
rm consensus-*
cd ..

# generate keys
python3 g_gen.py --N $1 --Ng $2 --f $3 --l $4 --r $6 --rf $8
python3 g_thresh_gen_n.py --N $2 --f $3 --l $4

# launch the consensus
# ./run_local_network_test_turritopsis.sh $1 $2 $3 $4 $5 $6 $7 $8
./run_local_network_test_sdumbo.sh $2 $2 $3 $4 $5 $6

(sleep 0.5; python3 readLogS.py --N $2) &