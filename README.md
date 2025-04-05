Proof-of-Concept implementation for Turritopsis. The code is forked from the implementation of Honeybadger-BFT protocol. This codebase also includes PoC implementations for sDumbo.

 To run the benchmarks at your machine (with Ubuntu 18.84 LTS), first install all dependencies as follows:

    sudo apt-get update
    sudo apt-get -y install make bison flex libgmp-dev libmpc-dev python3 python3-dev python3-pip libssl-dev

    wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
    tar -xvf pbc-0.5.14.tar.gz
    cd pbc-0.5.14
    sudo ./configure
    sudo make
    sudo make install
    cd ..

    sudo ldconfig /usr/local/lib

    cat <<EOF >/home/ubuntu/.profile
    export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
    EOF

    source /home/ubuntu/.profile
    export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
     
    git clone https://github.com/JHUISI/charm.git
    cd charm
    sudo ./configure.sh
    sudo make
    sudo make install
    sudo make test
    cd ..

    python3 -m pip install --upgrade pip
    sudo pip3 install gevent setuptools gevent numpy ecdsa pysocks gmpy2 zfec gipc pycrypto coincurve phe dill

A quick start to run Turritopsis for 15 round(1000 txs batch size) with one reconfiguration one node to join&leave can be:

    ./run_local_network_test.sh 10 9 2  1 1000 15

To run sDumbo-Hybrid for 15 round with a batch size of 1000tx, replace line 12 of run_local_network_test.sh with:

    python3 run_socket_node.py --sid 'sidA' --id $i --N $1 --Ng $2 --f $3 --l $4 --B $5 --K $6 --recon 100 --P "sdumbo-dy"  --O True &

    then run:

    ./run_local_network_test.sh 9 9 2 1 1000 15

 To run sDumbo-BFT for 15 round with a batch size of 1000tx can be:

    ./run_local_network_test.sh 9 9 2 0 1000 15

 To run ADKR with secp256k1 only for 15 round, replace line 12 of run_local_network_test.sh with:

    python3 run_socket_node.py --sid 'sidA' --id $i --N $1 --Ng $2 --f $3 --l $4 --B $5 --K $6 --recon 10 --P "adkr"  --O True &

To run ADKR with BLS12381 only for 15 round, replace line 12 of run_local_network_test.sh with:

    python3 run_socket_node.py --sid 'sidA' --id $i --N $1 --Ng $2 --f $3 --l $4 --B $5 --K $6 --recon 10 --P "adkr-bn"  --O True &

   then run:

    ./run_local_network_test.sh 9 9 2 1 1000 15

If you would like to test the code among AWS cloud servers (with Ubuntu 18.84 LTS). You can follow the commands inside run_local_network_test.sh to remotely start the protocols at all servers. An example to conduct the WAN tests from your PC side terminal can be:

    # the number of remove AWS servers
    N = 10
    # node scale is 9 and 1 new node to join 
    # public IPs --- This is the public IPs of AWS servers
     # public IPs
     pubIPsVar=([0]='18.212.40.33'
     [1]='54.174.146.217'
     [2]='3.95.161.117'
     [3]='44.201.240.203'
     [4]='3.133.145.7'
     [5]='18.191.29.105'
     [6]='52.14.198.166'
     [7]='3.133.150.146'
     [8]='13.56.115.98'
     [9]='52.53.241.12')

     
    # private IPs --- This is the private IPs of AWS servers
     priIPsVar=([0]='172.31.80.173'
     [1]='172.31.84.59'
     [2]='172.31.85.86'
     [3]='172.31.89.209'
     [4]='172.31.7.19'
     [5]='172.31.6.205'
     [6]='172.31.6.160'
     [7]='172.31.5.105'
     [8]='172.31.29.83'
     [9]='172.31.23.80')

    # Clone code to all remote AWS servers from github
     i=0; while [ $i -le $(( N-1 )) ]; do
     ssh -i "/home/your-name/your-key-dir/your-sk.pem" -o StrictHostKeyChecking=no ubuntu@${pubIPsVar[i]} "git clone --branch release https://github.com/fascy/dumbo-ng.git" &
     i=$(( i+1 ))
     done

    # Update IP addresses to all remote AWS servers 
     rm tmp_hosts.config
     i=0; while [ $i -le $(( N-1 )) ]; do
       echo $i ${priIPsVar[$i]} ${pubIPsVar[$i]} $(( $((200 * $i)) + 10000 )) >> tmp_hosts.config
       i=$(( i+1 ))
     done
     
     i=0; while [ $i -le $(( N-1 )) ]; do
       ssh -o "StrictHostKeyChecking no" -i "/home/your-name/keys/mule-oakland.pem" ubuntu@${pubIPsVar[i]} "cd dynamic; rm hosts.config"
       scp -i "/home/your-name/keys/mule-oakland.pem" tmp_hosts.config ubuntu@${pubIPsVar[i]}:/home/ubuntu/dynamic/hosts.config &
       i=$(( i+1 ))
     done

     
     # Start Protocols at all remote AWS servers
     i=0; while [ $i -le $(( N-1 )) ]; do   
         ssh -i "/home/your-name/keys/mule-oakland.pem" ubuntu@${pubIPsVar[i]} "export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib; export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib; cd dynamic; nohup python3 run_socket_node.py --sid 'sidA' --id $i --N 10 --Ng 9 --f 2 --l 1 --B 1000 --K 30 --recon 20 --P "sdumbo-dy" --O True > node-$i.out" &   
         i=$(( i+1 )); 
     done


     # Download logs from all remote AWS servers to your local PC
     i=0
     while [ $i -le $(( N-1 )) ]
     do
       scp -i "/home/your-name/your-key-dir/your-sk.pem" ubuntu@${pubIPsVar[i]}:/home/ubuntu/dumbo-ng/log/node-$i.log node-$i.log &
       i=$(( i+1 ))
     done


Here down below is the original README.md of HoneyBadgerBFT


# HoneyBadgerBFT
The Honey Badger of BFT Protocols.

<img width=200 src="http://i.imgur.com/wqzdYl4.png"/>

[![Travis branch](https://img.shields.io/travis/initc3/HoneyBadgerBFT-Python/dev.svg)](https://travis-ci.org/initc3/HoneyBadgerBFT-Python)
[![Codecov branch](https://img.shields.io/codecov/c/github/initc3/honeybadgerbft-python/dev.svg)](https://codecov.io/github/initc3/honeybadgerbft-python?branch=dev)

HoneyBadgerBFT is a leaderless and completely asynchronous BFT consensus protocols.
This makes it a good fit for blockchains deployed over wide area networks
or when adversarial conditions are expected.
HoneyBadger nodes can even stay hidden behind anonymizing relays like Tor, and
the purely-asynchronous protocol will make progress at whatever rate the
network supports.

This repository contains a Python implementation of the HoneyBadgerBFT protocol.
It is still a prototype, and is not approved for production use. It is intended
to serve as a useful reference and alternative implementations for other projects.

## Development Activities

Since its initial implementation, the project has gone through a substantial
refactoring, and is currently under active development.

At the moment, the following three milestones are being focused on:

* [Bounded Badger](https://github.com/initc3/HoneyBadgerBFT-Python/milestone/3)
* [Test Network](https://github.com/initc3/HoneyBadgerBFT-Python/milestone/2<Paste>)
* [Release 1.0](https://github.com/initc3/HoneyBadgerBFT-Python/milestone/1)

A roadmap of the project can be found in [ROADMAP.rst](./ROADMAP.rst).


### Contributing
Contributions are welcomed! To quickly get setup for development:

1. Fork the repository and clone your fork. (See the Github Guide
   [Forking Projects](https://guides.github.com/activities/forking/) if
   needed.)

2. Install [`Docker`](https://docs.docker.com/install/). (For Linux, see
   [Manage Docker as a non-root user](https://docs.docker.com/install/linux/linux-postinstall/#manage-docker-as-a-non-root-user)
   to run `docker` without `sudo`.)

3. Install [`docker-compose`](https://docs.docker.com/compose/install/).

4. Run the tests (the first time will take longer as the image will be built):

   ```bash
   $ docker-compose run --rm honeybadger
   ```

   The tests should pass, and you should also see a small code coverage report
   output to the terminal.

If the above went all well, you should be setup for developing
**HoneyBadgerBFT-Python**!

## License
This is released under the CRAPL academic license. See ./CRAPL-LICENSE.txt
Other licenses may be issued at the authors' discretion.
