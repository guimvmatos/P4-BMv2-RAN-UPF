#!/bin/bash

sudo ip link set dev lo up
sudo ip link set dev enp0s9 up
sudo ip link set dev enp0s10 up

ip link set enp0s9 mtu 1500
ip link set enp0s10 mtu 9000

apt-get install curl
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py
python get-pip.py
pip install ipaddr

cd /home/p4/behavioral-model/
./configure --enable-debugger
make
make install


p4c -b bmv2 ran.p4 -o ./
#simple_switch --log-console -i 1@enp0s9 -i 2@enp0s10 ran.json
simple_switch -i 1@enp0s9 -i 2@enp0s10 ran.json
cat commands2.txt | simple_switch_CLI