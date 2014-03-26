#pragma once

struct EthernetHead
{
	unsigned char bDestMac[6];//dest MAC
	unsigned char bSourceMac[6];//source MAC
	unsigned short usEthernetType;//ethernet type
};

struct ArpHead
{
	unsigned short usHardWareType;//hardware type
	unsigned short usProtocolType;//format of hardware adress
	unsigned char ucMacLength;//length of hardware addrdss
	unsigned char ucProtocolLength;///length of protocol type
	unsigned short usOpetion;//request or ack
	unsigned char SourceMac[6];//source MAC address
	unsigned long dwSourecIP; //source proco addr
    unsigned char DestMac[6];//target hardware address
    unsigned long dwDestIP;//target proco addr
	unsigned char Padding[18];
};
struct ArpPacket
{
	EthernetHead theEthernetHead;
	ArpHead theArpHead;
};
struct IpHead
{
    unsigned char  ucVersionAndHeadLength;        // Version (4 bits) + Internet header length (4 bits)
    unsigned char  ucTos;            // Type of service 
    unsigned short usTotalLength;           // Total length 
    unsigned short usIdentification; // Identification
    unsigned short usFlagsAndFragmentOffset;       // Flags (3 bits) + Fragment offset (13 bits)
    unsigned char  ucTtl;            // Time to live
    unsigned char  ucProtocol;          // Protocol
    unsigned short usCrc;            // Header checksum
    unsigned long  dwSourceAddr;      // Source address
    unsigned long  dwDestAddr;      // Destination address
};
struct TcpHead            //����TCP �ײ�
{
	USHORT usSourcePort; //16 λԴ�˿�
	USHORT usDestPort; //16 λĿ�Ķ˿�
	ULONG dwSeq;
	ULONG dwAck;
	UCHAR ucLength;           //4 λ�ײ�����/4 λ������
	UCHAR ucFlag;            //6 λ��־λ
	USHORT usWindow; //16 λ���ڴ�С
	USHORT usCrc;//16 λУ���
	USHORT usUrgent;//16 λ��������ƫ����
	UINT unMssOpt;
	USHORT usNopOpt;
	USHORT usSackOpt;
};
struct IpPacket
{
	EthernetHead theEthHead;
	IpHead theIpHead;
};
struct TcpPacket
{
	IpPacket theIpPacket;
	TcpHead theTcpHead;
};
struct TcpFakeHeader
{
    DWORD dwSourceAddr;						//Դ��ַ
    DWORD dwDestAddr;						//Ŀ�ĵ�ַ
    BYTE bZero;							//�ÿ�
    BYTE bProtocolType;							//Э������
    USHORT bTcpLength;						//TCP����
};
struct UdpFakeHeader
{
    DWORD dwSourceAddr;						//Դ��ַ
    DWORD dwDestAddr;						//Ŀ�ĵ�ַ
    BYTE bZero;							//�ÿ�
    BYTE bProtocolType;							//Э������
    USHORT bUdpLength;						//UDP����
};
struct IcmpHead
{
	unsigned char ucType;
	unsigned char ucCode;
	unsigned short usCrc;
	unsigned short usIdentifier;
	unsigned short usSequenceNumber;
};

struct IcmpPacket
{
	IpPacket theIpPacket;
	IcmpHead theIcmpHead;
};
struct UdpHead
{
	u_short usSourcePort;			// Source port
	u_short usDestPort;			// Destination port
	u_short usLength;			// Datagram length
	u_short usCrc;			// Checksum
	u_short usData;
};
struct UdpPacket
{
	EthernetHead theEthHead;
	IpHead theIpHead;
	UdpHead theUdpHead;
};
USHORT CheckSum(const char *buf, int size) ;
USHORT CheckSum(USHORT *buffer, int size);
unsigned short TcpCheckSum(const char *pTcpData, const char *pPshData, UINT nTcpCount);
unsigned short UdpCheckSum(const char *pUdpData, const char *pPshData, UINT nUdpCount);
class SetBoolTrue
{
public:
	SetBoolTrue(bool *pbValue);
	~SetBoolTrue();
private:
	bool * pbValue;
};
class ThreadSyn
{
public:
	ThreadSyn();
	~ThreadSyn();
};