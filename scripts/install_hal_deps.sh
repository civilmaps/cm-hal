#!/bin/bash

apt-get update -y
apt-get install -y build-essential intltool wget libcurl4-openssl-dev openssl libssl-dev

ldconfig

#TODO: check if path modifications are needed
echo 'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/lib' | tee -a /root/.bashrc
echo 'export LD_LIBRARY_PATH=/usr/local/lib' | tee -a /root/.bashrc
#echo 'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/lib' | tee -a /home/"$1"/.bashrc
#echo 'export LD_LIBRARY_PATH=/usr/local/lib' | tee -a /home/"$1"/.bashrc

#Install JSON CPP
chmod +x install_json_cpp.sh && /bin/bash install_json_cpp.sh

#Install POCO, we currently use v1.5.3
chmod +x install_poco.sh && /bin/bash install_poco.sh

# Install pcap library
apt-get install -y libpcap0.8-dev

#reboot
