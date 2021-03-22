# sec_agent_demo

#### key words ####
# 1.创建虚拟网卡 Tun/TAP 
# 2.VPN
# 3.抓取、截获报文
# 4.修改报文、 TCP Options字段
# 5.

####创建虚拟网卡####

### server configure
#ip tuntap add tun0 mode tun
#ip addr add 192.168.8.138/24 dev tun111
#ip link set dev tun0 up
#./simple_ip  -i tun0 -s -d
# nc -l 9999 (模拟起一个服务让对端连接)

### client configure
#ip tuntap add tun0 mode tun
#ip addr add 192.168.8.139/24 dev tun111
#ip link set dev tun0 up
#./simple_ip -i tun0 -c 10.26.28.84(server ip)
# nc 192.168.8.138 9999 (模拟本机发出的报文)


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
     nc -l 9999    <------------  nc 192.168.8.138 9999

