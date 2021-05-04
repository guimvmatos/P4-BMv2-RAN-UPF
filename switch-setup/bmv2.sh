#!/bin/bash

sudo ip link set dev lo up
sudo ip link set dev enp0s9 up
sudo ip link set dev enp0s10 up

p4c -b bmv2 ran.p4 -o ./
nohup simple_switch -i 1@enp0s9 -i 2@enp0s10 ran.json &