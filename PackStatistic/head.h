#pragma pack(1)
////////协议头部以及协议包
struct IpHead
{	
	unsigned char hdr_len:4;
	unsigned char version:4;
	unsigned char tos;
	unsigned short total_len;
	unsigned short identifier;
	unsigned short frag_and_flags;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short check_sum;
	unsigned long sourceIP;
	unsigned long destIP;
};
struct EthernetHead
{
	unsigned char dest_mac[6];			//目标主机mac地址
	unsigned char source_mac[6];		//源mac地址
	unsigned short eh_type;				//ethernet网类型
};
struct Arphead{
	unsigned short hardware_type;		//硬件类型
	unsigned short protocol;			//协议类型
	unsigned char add_len;				//mac地址长度 6B
	unsigned char pro_len;				//ip地址长度 4B
	unsigned short option;				//操作:1/2
	unsigned char sour_addr[6];
	unsigned long sour_ip;
	unsigned char dest_addr[6];
	unsigned long dest_ip;
	unsigned char padding[18];           //填充字节
};

struct ArpPacket{
	EthernetHead eth;						//ethernet网头部
	Arphead arp;							//arp数据帧头部
};
struct IpPacket
{
	EthernetHead ethHead;
	IpHead ipHead;
};

struct TcpHead            //定义TCP 首部
{
	unsigned short sourcePort; //16 位源端口
	unsigned short destPort; //16 位目的端口
	unsigned long seq;
	unsigned long ack;
	unsigned char length;           //4 位首部长度/4 位保留字
	unsigned char flag;            //6 位标志位
	unsigned short window; //16 位窗口大小
	unsigned short crc;//16 位校验和
	unsigned short urgent;//16 位紧急数据偏移量
};
struct TcpPacket
{
	IpPacket ipPacket;
	TcpHead tcpHead;
};


struct UdpHead
{
	unsigned short sourcePort;			// Source port
	unsigned short destPort;			// Destination port
	unsigned short length;			// Datagram length
	unsigned short crc;			// Checksum
};
struct UdpPacket
{
	IpPacket ipPacket;
	UdpHead udpHead;
};
//tcp伪头部
struct TcpFakeHeader
{
    unsigned long sourceIP;
	unsigned long destIP;
    BYTE bZero;					//置空
	unsigned char protocol;
    unsigned short tcpLength;	//TCP长度
};
//udp伪头部
struct UdpFakeHeader
{
    unsigned long sourceIP;
	unsigned long destIP;
    BYTE bZero;					//置空
	unsigned char protocol;
    unsigned short udpLength;	//UDP长度
};
///ICMP基本头部
struct IcmpBaseHead
{
	unsigned char type;
	unsigned char code;
	unsigned short cksum;
};
struct IcmpBasePacket
{
	IpPacket ipPacket;
	IcmpBaseHead icmpBaseHead;

};

//回显请求与应答头部
struct IcmpEchoHeader
{
	IcmpBaseHead icmpbasehead;
	unsigned short id;
	unsigned short seq;

};
//基本差错头部
struct IcmpErrorHeader
{
	IcmpBaseHead icmpbasehead;
	unsigned long unused;
	
};
struct IcmpEchoPacket
{
	IpPacket ipPacket;
	IcmpEchoHeader icmpEchoHeader;	
};
///ICMP超时差错报文
struct IcmpErrorPacket
{
	IpPacket ipPacket;
	IcmpErrorHeader icmpErrorHeader;
	IpHead ipHead;
	IcmpEchoHeader icmpEchoHeader;
};
//ICMP不可达报文
struct IcmpUnReachablePacket
{
	IpPacket ipPacket;
	IcmpErrorHeader icmpErrorHeader;
	IpHead iPHead;
	UdpHead udpHead;
};
#pragma pack()