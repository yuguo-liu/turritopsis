# How to Deploy the Turritopsis

## Enironment Requirements

1. OS: Ubuntu 18.04/20.04
2. Python: 3.7/3.8
3. Rust

## Deploy Step by Step

1. install the necessary dependencies

```bash
sudo apt-get update
sudo apt-get -y install make bison flex libgmp-dev libmpc-dev python3 python3-dev python3-pip libssl-dev
```

2. install Rust and set it nightly

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
rustup install nightly
rustup default nightly
```

3. git clone the turritopsis

```bash
git clone git@github.com:fascy/turritopsis.git
cd turritopsis
```

4. install pbc

```bash
wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar -xvf pbc-0.5.14.tar.gz
cd pbc-0.5.14
sudo ./configure
sudo make
sudo make install
cd ..
```

5. environmental configuration

```bash
sudo ldconfig /usr/local/lib

cat <<EOF >$HOME/.profile
export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
EOF

source $HOME/.profile
export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
```

6. install charm

```bash
git clone git@github.com:JHUISI/charm.git
cd charm
sudo ./configure.sh
sudo make
sudo make install
sudo pip3 install pytest==6.2.5
sudo make test
cd ..
```

7. install necessary libraries of Python

```bash
python3 -m pip install --upgrade pip
sudo pip3 install --only-binary=:all: zfec
sudo pip3 install gevent setuptools gevent numpy ecdsa pysocks gmpy2 zfec gipc pycrypto coincurve phe dill
```

8. install pypairing

```bash
cd pairing
# modify the following commend properly with your real Python version
sudo chmod 777 /usr/local/lib/python3.8/dist-packages/
sudo pip3 install setuptools==68.0.0
sudo pip3 install importlib-metadata==6.7.0

# visit https://blog.csdn.net/fascy/article/details/138803123 and do the modification before going on
sudo visudo
```

replace
`Defaults env_reset`
with
`Defaults !env_reset`, then quit with `ctrl+o` (save) and `ctrl+x` (exit)

```
sudo vim  ~/.bashrc
```

add `alias sudo='sudo env "PATH=$PATH"'`

```
source ~/.bashrc
sudo python3 setup.py install
sudo pip3 install .
cd ..
```

9. quick test

```bash
./run_local_network_test.sh 10 9 2 1 1000 15
```
