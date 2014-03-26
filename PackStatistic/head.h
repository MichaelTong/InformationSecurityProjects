#pragma pack(1)
////////Э��ͷ���Լ�Э���
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
	unsigned char dest_mac[6];			//Ŀ������mac��ַ
	unsigned char source_mac[6];		//Դmac��ַ
	unsigned short eh_type;				//ethernet������
};
struct Arphead{
	unsigned short hardware_type;		//Ӳ������
	unsigned short protocol;			//Э������
	unsigned char add_len;				//mac��ַ���� 6B
	unsigned char pro_len;				//ip��ַ���� 4B
	unsigned short option;				//����:1/2
	unsigned char sour_addr[6];
	unsigned long sour_ip;
	unsigned char dest_addr[6];
	unsigned long dest_ip;
	unsigned char padding[18];           //����ֽ�
};

struct ArpPacket{
	EthernetHead eth;						//ethernet��ͷ��
	Arphead arp;							//arp����֡ͷ��
};
struct IpPacket
{
	EthernetHead ethHead;
	IpHead ipHead;
};

struct TcpHead            //����TCP �ײ�
{
	unsigned short sourcePort; //16 λԴ�˿�
	unsigned short destPort; //16 λĿ�Ķ˿�
	unsigned long seq;
	unsigned long ack;
	unsigned char length;           //4 λ�ײ�����/4 λ������
	unsigned char flag;            //6 λ��־λ
	unsigned short window; //16 λ���ڴ�С
	unsigned short crc;//16 λУ���
	unsigned short urgent;//16 λ��������ƫ����
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
//tcpαͷ��
struct TcpFakeHeader
{
    unsigned long sourceIP;
	unsigned long destIP;
    BYTE bZero;					//�ÿ�
	unsigned char protocol;
    unsigned short tcpLength;	//TCP����
};
//udpαͷ��
struct UdpFakeHeader
{
    unsigned long sourceIP;
	unsigned long destIP;
    BYTE bZero;					//�ÿ�
	unsigned char protocol;
    unsigned short udpLength;	//UDP����
};
///ICMP����ͷ��
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

//����������Ӧ��ͷ��
struct IcmpEchoHeader
{
	IcmpBaseHead icmpbasehead;
	unsigned short id;
	unsigned short seq;

};
//�������ͷ��
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
///ICMP��ʱ�����
struct IcmpErrorPacket
{
	IpPacket ipPacket;
	IcmpErrorHeader icmpErrorHeader;
	IpHead ipHead;
	IcmpEchoHeader icmpEchoHeader;
};
//ICMP���ɴﱨ��
struct IcmpUnReachablePacket
{
	IpPacket ipPacket;
	IcmpErrorHeader icmpErrorHeader;
	IpHead iPHead;
	UdpHead udpHead;
};
#pragma pack()