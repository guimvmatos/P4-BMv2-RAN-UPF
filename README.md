# P4 BMv2 RAN/UPF
This is a P4-BMv2 model of RAN and UPF to use use with INCA. To use this code, you will need following requirements:

- Virtualbox
- Vagrant
- Netronome Agilio SmartNIC

# Purpose of this repo

Simulate RAN and UPF operations on a 5G simulated network. Basically, simulate RAN and UPF operations in a simulated 5G network. Basically, this code encapsulates and de-encapsulates IPv6 traffic in GTP headers and forwards it to the destination client or network. 

# Commands
- ``` vagrant up ``` will create two virtual machines.
- ``` vagrant ssh bmv2-1 ``` will make a ssh connection in a virtual machine bmv2-1 (RAN). This virtual machine has IPv6 addresses fc00::1 and fc10::1.
- ``` vagrant ssh bmv2-2 ``` will make a ssh connection in a virtual machine bmv2-2 (UPF). This virtual machine has IPv6 addresses fc00::5 and fc20::1.


# Starting the services.
On both virtual machines, you must create a json file from P4 code and start BMv2 Switch with it.
```
sudo ip link set dev lo up 
sudo ip link set dev enp0s9 up
sudo ip link set dev enp0s10 up
ip link set enp0s9 mtu 1500
ip link set enp0s10 mtu 9000
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py
python get-pip.py
pip install ipaddr
cd /home/p4/behavioral-model
./configure --enable-debugger
make
make install
p4c -b bmv2 ran.p4 -o ./
simple_switch -i 1@enp0s9 -i 2@enp0s10 ran.json
```
On another terminal:

```simple_switch_CLI```

and then copy and past all code from `commands2.txt`

#Considerations

This code and it topology is part of INCA project. If you want to see more and understand it better, please visit. 
