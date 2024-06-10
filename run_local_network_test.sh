#!/bin/sh
source /home/gyz/adkg/venv/bin/activate Python3.6
# N f B K
echo "start.sh <N> <F> <B> <K>"

# python3 run_trusted_key_gen.py --N $1 --f $2

killall python3
i=0
while [ "$i" -lt $1 ]; do
    echo "start node $i..."
    python3 run_socket_node.py --sid 'sidA' --id $i --N $1 --Ng $2 --f $3 --l $4 --B $5 --K $6 --recon 10 --P "sdumbo-dy"  --O True &
    # python3 run_socket_node.py --sid 'sidA' --id $i --N $1 --f $2 --B $3 --S 100 --P "ng" --D True --O True --C $4 &
    # python3 run_socket_node.py --sid 'sidA' --id $i --N $1 --f $2 --B $3 --K $4 --P "sdumbo" --O True &

    i=$(( i + 1 ))

done