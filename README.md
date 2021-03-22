# sec_agent_demo
#  

####创建虚拟网卡####

### server configure
ip tuntap add tun0 mode tun
ip addr add 192.168.8.138/24 dev tun111
ip link set dev tun0 up
./simple_ip  -i tun0 -s -d


### client configure
ip tuntap add tun0 mode tun
ip addr add 192.168.8.139/24 dev tun111
ip link set dev tun0 up
./simple_ip -i tun0 -c 10.26.28.84(server ip)



####删除虚拟网卡####
ip tuntap del dev tun0 mode tun




#####################################################

# ---------------                 ---------------   #
# |10.26.28.84  |<------------- > |10.26.28.4   |   #
# |     ^       |                 |     ^       |   #
# |     |       |                 |     |       |   #
# |192.168.8.138|                 |192.168.8.139|   #
# ---------------                 ---------------   #
#      Sever                           Client       #