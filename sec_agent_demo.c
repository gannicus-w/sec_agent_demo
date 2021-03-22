/**************************************************************************
 * simpletun.c                                                            *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap    *
 * interfaces and TCP. DO NOT USE THIS PROGRAM FOR SERIOUS PURPOSES.      *
 *                                                                        *
 * You have been warned.                                                  *
 *                                                                        *
 * (C) 2010 Davide Brini.                                                 *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/ 
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <iostream>
/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define PORT 55559
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef unsigned int        DWORD;
using namespace std;
typedef struct tIPPackHead
{
 
	BYTE ver_hlen;      //IP协议版本和IP首部长度。高4位为版本，低4位为首部的长度(单位为4bytes)
	BYTE byTOS;         //服务类型
	WORD wPacketLen;    //IP包总长度。包括首部，单位为byte。[Big endian]
	WORD wSequence;     //标识，一般每个IP包的序号递增。[Big endian]
 
	union
	{
		WORD Flags;     //标志
		WORD FragOf;    //分段偏移
	};
	BYTE byTTL;            //生存时间 
	BYTE byProtocolType;   //协议类型，见PROTOCOL_TYPE定义
	WORD wHeadCheckSum;    //IP首部校验和[Big endian]
	DWORD dwIPSrc;         //源地址
	DWORD dwIPDes;         //目的地址
	//BYTE Options;          //选项
} IP_HEAD;

typedef struct tTCPPackHead
{
   WORD  wPSrc;     // src port 
   WORD  wPDst;     // dst port
   DWORD dwSeq;     // seq number
   DWORD dwAckSeq;  // ack seq number
   BYTE  res1:4,
         wDoff:4;   // tcp header length, 高4位有效,低4位保留
         
   BYTE  bFlags:6,   // 标记位, 高6位有效,低2位保留
         res2:2;
   WORD  wWindow;   // 窗口
   WORD  wCheck;    // 校验和
   WORD  wUrgPtr;   // 紧急指针
} TCP_HEAD;

// debug info
typedef enum
{
    ReadFromTun = 0,
    Write2Net   = 1,
    ReadFromNet = 2,
    Write2Tun   = 3,
} Debug_info_type_t;

int debug;
char *progname;
int cnt0, cnt1, cnt2, cnt3;
uint16_t in_checksum(const void* buf, int len)
{
    const uint16_t* data = static_cast<const uint16_t*>(buf);
    int sum = 0;
    for (int i = 0; i < len; i+=2)
    {
        sum += *data++;
    }
    // while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

/**************************************************************************
 * Modify_TcpHeader: modify tcp header. eg: add tcp options.              * 
 * Notes: ip header len=sizeof(IP_HEAD). (the opt field is not considered)*              
 *        ip total len=the entire IP packet length                        *
 *        tcp header len=fixed field(20) + options field([0,40])          *
 *        tcp segement len(payload/data)=ip total len - ip head len       *
 *                                      - tcp head len                    *
 **************************************************************************/
char* Modify_TcpHeader(char *buf, int len)
{
    IP_HEAD *iphead, *newip;
    TCP_HEAD *tcphead, *newtcp;
    
    iphead = (IP_HEAD*)buf;
    int ip_head_len = (iphead->ver_hlen & 0x0F) << 2;
    iphead->wPacketLen = htons(ntohs(iphead->wPacketLen)+4);
    iphead->wHeadCheckSum = 0;
    iphead->wHeadCheckSum = in_checksum(iphead, sizeof(IP_HEAD));
     
    tcphead = (TCP_HEAD *)(buf + ip_head_len);  //iphead->ver_hlen

    int tcp_head_len = tcphead->wDoff*4; //tcp heaer 除了固定的20字节外还可能包括options字段
    int tcp_seg_len = len - ip_head_len - tcp_head_len;    // tcp的payload,不包括在tcp头长度内

    char tcp_opts_data[4];
    unsigned short pid = 996;
    tcp_opts_data[0] = 253;  // opts的类型
    tcp_opts_data[1] = 4;    //  opts info的大小
    memcpy(tcp_opts_data+2,&pid,2); // opts info

    char *whole_packet = (char *) malloc(len + 4);

    memcpy(whole_packet, buf, ip_head_len + tcphead->wDoff*4);// eg:20+40
    memcpy(whole_packet + (ip_head_len + tcphead->wDoff*4), tcp_opts_data, 4); //options
    if (tcp_seg_len > 0) {
        memcpy(whole_packet + (ip_head_len + tcphead->wDoff*4 + 4), buf + (ip_head_len + tcphead->wDoff*4), tcp_seg_len);
    }
    newip = (IP_HEAD*)whole_packet;
    newtcp = (TCP_HEAD *)(whole_packet + ip_head_len);

    char* pseudo = whole_packet + (len + 4);
    pseudo[0] = 0;
    pseudo[1] = IPPROTO_TCP;
    pseudo[2] = 0;
    pseudo[3] = len - ip_head_len + 4;

    newtcp->wDoff += 1; // @@@ 临时写法，非标准写法
    newtcp->wCheck = 0;
    newtcp->wCheck = in_checksum(&newip->dwIPSrc, len - ip_head_len + 4 + 12);

    return whole_packet;
}
  
int DecodeIP(char *buf, int len, char tags)
{
	int n = len;
	if (n >= sizeof(IP_HEAD))
	{
		IP_HEAD iphead;
		iphead = *(IP_HEAD*)buf;

        switch (tags)
        {
            case ReadFromTun:
		        cout << "第 "<<cnt0++<<" 个IP数据包信息[Read From Tun]：" << endl;
                break;
            case Write2Net:
		        cout << "第 "<<cnt1++<<" 个IP数据包信息(Write to Net):" << endl;
                break;
            case ReadFromNet:
		        cout << "第 "<<cnt2++<<" 个IP数据包信息[Read From Net]:" << endl;
                break;
            case Write2Tun:
		        cout << "第 "<<cnt3++<<" 个IP数据包信息(Write to Tun)：" << endl;
                break;
            default:
                break;
        }
		cout << "协议版本:" <<(iphead.ver_hlen >> 4) << endl;
		cout << "首部长度:" << ((iphead.ver_hlen & 0x0F) << 2) << endl;//单位为4字节
		cout << "服务类型:Priority: " << (iphead.byTOS >> 5) << ",Service: " << ((iphead.byTOS >> 1) & 0x0f) << endl;
		cout << "IP包总长度:" << ntohs(iphead.wPacketLen) << endl; //网络字节序转为主机字节序
		cout << "标识:" << ntohs(iphead.wSequence) << endl;
		cout << "标志位:" << "DF=" << ((iphead.Flags >> 14) & 0x01) << ",MF=" << ((iphead.Flags >> 13) & 0x01) << endl;
		cout << "片偏移:" << (iphead.FragOf & 0x1fff) << endl;
		cout << "生存周期:" << (int)iphead.byTTL << endl;
		cout << "协议类型:" << int(iphead.byProtocolType) << endl;
		cout << "首部校验和:" << ntohs(iphead.wHeadCheckSum) << endl;
		cout << "源地址:" << inet_ntoa(*(in_addr*)&iphead.dwIPSrc) << endl;
		cout << "目的地址:" << inet_ntoa(*(in_addr*)&iphead.dwIPDes) << endl;
 
		cout << "=================================================================" << endl << endl;
	}else{
        cout << "***包长不足：" << n << " < " << sizeof(IP_HEAD) << endl;
    }
    
	return 0;
}
#define DecodeIP_Write2Net   DecodeIP
#define DecodeIP_Write2Tun   DecodeIP 
#define DecodeIP_ReadFromTun DecodeIP
#define DecodeIP_ReadFromNet DecodeIP 

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            must reserve enough space in *dev.                          *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {
 
  struct ifreq ifr;
  int fd, err;
  const char *clonedev = "/dev/net/tun";
 
  if( (fd = open(clonedev , O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }
 
  memset(&ifr, 0, sizeof(ifr));
 
  ifr.ifr_flags = flags;
 
  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }
 
  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }
 
  strcpy(dev, ifr.ifr_name);
 
  return fd;
}
 
/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  int nread;
  
  if((nread=read(fd, buf, n)) < 0){
    perror("Reading data");
    exit(1);
  }
  //DecodeIP_ReadFromNet(buf, nread);
  
 
  printf("read len:%d -> ", nread);
  for(int i = 0;i < nread;i++){
    printf("%02X ", (unsigned char)buf[i]);
    if (i !=0 && i % 16 == 0) {
        printf("\n");
    }
  }
  printf("\n");
  return nread;
}
 
/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;
  if((nwrite=write(fd, buf, n)) < 0){
    perror("Writing data");
    exit(1);
  }
 
  printf("write: ");
  for(int i = 0;i < n;i++){
  	printf("%02X ",(unsigned char)buf[i]);
    if (i != 0 && i % 16 == 0) {
        printf("\n");
    }
  }
  printf("\n");
  return nwrite;
}
 
/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts them into "buf".     *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
 
 
int read_n(int fd, char *buf, int n) {
 
  int nread, left = n;
  while(left > 0) {
    if ((nread = cread(fd, buf, left)) == 0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}
 
// 读取ipv4包头，获得需要继续读的长度
int read_ipv4_len_left(int fd ,char *buf){
    cout << "==read_ipv4_len_left==" << endl;
    int nread;
    nread = read_n(fd, buf, sizeof(IP_HEAD));
    cout << "==read_ipv4_len_left== -> read_n" << nread << endl;
    if (nread == 0){
        cout << "read_ipv4_len_left get 0." << endl;
        return 0;
    }
    
    IP_HEAD iphead;
    iphead = *(IP_HEAD*)buf;
    DecodeIP_ReadFromNet(buf, nread, ReadFromNet);
    int len_to_read = ntohs(iphead.wPacketLen) - sizeof(IP_HEAD);
    cout << "此IP包总长度:    " << ntohs(iphead.wPacketLen) << endl;
    cout << "剩余要读取的长度:" << len_to_read << endl;
    return len_to_read;
} 
/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(const char *msg, ...){
  
  va_list argp;
  
  if(debug) {
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
  }
}
 
/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(const char *msg, ...) {
 
  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}
 
/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}
 
int main(int argc, char *argv[]) {
  cout << "ip 包头:" << sizeof(IP_HEAD) << endl;
  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int maxfd;
  uint16_t nread, nwrite, plength;
  char buffer[BUFSIZE];
  struct sockaddr_in local, remote;
  char remote_ip[16] = "";            /* dotted quad IP string */
  unsigned short int port = PORT;
  int sock_fd, net_fd, optval = 1;
  socklen_t remotelen;
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;
 
  progname = argv[0];
  
  /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:p:uahd")) > 0) {
    switch(option) {
      case 'd':
        debug = 1;
        break;
      case 'h':
        usage();
        break;
      case 'i':
        strncpy(if_name,optarg, IFNAMSIZ-1);
        break;
      case 's':
        cliserv = SERVER;
        break;
      case 'c':
        cliserv = CLIENT;
        strncpy(remote_ip,optarg,15);
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'u':
        flags = IFF_TUN;
        break;
      case 'a':
        flags = IFF_TAP;
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }
 
  argv += optind;
  argc -= optind;
 
  if(argc > 0) {
    my_err("Too many options!\n");
    usage();
  }
 
  if(*if_name == '\0') {
    my_err("Must specify interface name!\n");
    usage();
  } else if(cliserv < 0) {
    my_err("Must specify client or server mode!\n");
    usage();
  } else if((cliserv == CLIENT)&&(*remote_ip == '\0')) {
    my_err("Must specify server address!\n");
    usage();
  }
 
  /* initialize tun/tap interface */
  if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }
 
  do_debug("Successfully connected to interface %s\n", if_name);
 
  if ( (sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket()");
    exit(1);
  }
 
  if(cliserv == CLIENT) {
    /* Client, try to connect to server */
 
    /* assign the destination address */
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(remote_ip);
    remote.sin_port = htons(port);
 
    /* connection request */
    if (connect(sock_fd, (struct sockaddr*) &remote, sizeof(remote)) < 0) {
      perror("connect()");
      exit(1);
    }
 
    net_fd = sock_fd;
    do_debug("CLIENT: Connected to server %s\n", inet_ntoa(remote.sin_addr));
    
  } else {
    /* Server, wait for connections */
 
    /* avoid EADDRINUSE error on bind() */
    if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0) {
      perror("setsockopt()");
      exit(1);
    }
    
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(port);
    if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0) {
      perror("bind()");
      exit(1);
    }
    
    if (listen(sock_fd, 5) < 0) {
      perror("listen()");
      exit(1);
    }
    
    /* wait for connection request */
    remotelen = sizeof(remote);
    memset(&remote, 0, remotelen);
    if ((net_fd = accept(sock_fd, (struct sockaddr*)&remote, &remotelen)) < 0) {
      perror("accept()");
      exit(1);
    }
 
    do_debug("SERVER: Client connected from %s\n", inet_ntoa(remote.sin_addr));
  }
  
  /* use select() to handle two descriptors at once */
  maxfd = (tap_fd > net_fd)?tap_fd:net_fd;
 
  while(1) {
    int ret;
    fd_set rd_set;
 
    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set); FD_SET(net_fd, &rd_set);
 
    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);
 
    if (ret < 0 && errno == EINTR){
      continue;
    }
 
    if (ret < 0) {
      perror("select()");
      exit(1);
    }
 
    if(FD_ISSET(tap_fd, &rd_set)) {
      /* data from tun/tap: just read it and write it to the network */
      
      nread = cread(tap_fd, buffer, BUFSIZE);   // BUFSIZE 2000，一般不会超过ip包最长长度
      printf("tap recv ip packet ver：%x\n", (char)(*buffer));  
      if((char)(*buffer) == 0x45){ 
          tap2net++;
          DecodeIP_ReadFromTun(buffer, nread, ReadFromTun);
          do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);
 
          // @@@@ 写之前将对报文的tcp header 增加options字段
          // Modify_TcpHeader(buffer, nread);
          nwrite = cwrite(net_fd, Modify_TcpHeader(buffer, nread), nread+4);// @@@临时+4,非标准写法
          DecodeIP_Write2Net(buffer, nread, Write2Net);
          do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
          
      }else{
          printf("Not ipv4 packet, drop this.");
      }
      
    }
 
    if(FD_ISSET(net_fd, &rd_set)) {
      /* data from the network: read it, and write it to the tun/tap interface. 
       * We need to read the length first, and then the packet */
 
      /* Read length */ 
      nread = read_ipv4_len_left(net_fd, (char *)buffer);//buffer 是共用的一个临时变量
      if(nread == 0) {
          /* ctrl-c at the other end */
          cout << "get nread==0, break." << endl;
          break;
      }else{
          
      }
      net2tap++;
      
      char *whole_packet = (char *) malloc(sizeof(IP_HEAD) + nread);
      memcpy(whole_packet, buffer, sizeof(IP_HEAD));
      
      /* read packet */
      nread = read_n(net_fd, buffer, nread);// 读到buffer里
      memcpy(whole_packet + sizeof(IP_HEAD), buffer, nread);
      do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);
      
      /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
      nwrite = cwrite(tap_fd, (char*)whole_packet, sizeof(IP_HEAD) + nread);
      DecodeIP_Write2Tun(whole_packet, sizeof(IP_HEAD) + nread, Write2Tun);
      do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
    }
  }
  
  return(0);
}

