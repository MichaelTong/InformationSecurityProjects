// stdafx.h : ��׼ϵͳ�����ļ��İ����ļ���
// ���Ǿ���ʹ�õ��������ĵ�
// ��Ŀ�ض��İ����ļ�

#pragma once

#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN		// �� Windows ��ͷ���ų�����ʹ�õ�����
#endif

// ���������ʹ��������ָ����ƽ̨֮ǰ��ƽ̨�����޸�����Ķ��塣
// �йز�ͬƽ̨����Ӧֵ��������Ϣ����ο� MSDN��
#ifndef WINVER				// ����ʹ�� Windows 95 �� Windows NT 4 ����߰汾���ض����ܡ�
#define WINVER 0x0400		//Ϊ Windows98 �� Windows 2000 �����°汾�ı�Ϊ�ʵ���ֵ��
#endif

#ifndef _WIN32_WINNT		// ����ʹ�� Windows NT 4 ����߰汾���ض����ܡ�
#define _WIN32_WINNT 0x0400		//Ϊ Windows98 �� Windows 2000 �����°汾�ı�Ϊ�ʵ���ֵ��
#endif						

#ifndef _WIN32_WINDOWS		// ����ʹ�� Windows 98 ����߰汾���ض����ܡ�
#define _WIN32_WINDOWS 0x0410 //Ϊ Windows Me �����°汾�ı�Ϊ�ʵ���ֵ��
#endif

#ifndef _WIN32_IE			// ����ʹ�� IE 4.0 ����߰汾���ض����ܡ�
#define _WIN32_IE 0x0400	//Ϊ IE 5.0 �����°汾�ı�Ϊ�ʵ���ֵ��
#endif

#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS	// ĳЩ CString ���캯��������ʽ��

// �ر� MFC ��ĳЩ��������������ȫ���Եľ�����Ϣ������
#define _AFX_ALL_WARNINGS

#include <afxwin.h>         // MFC ���ĺͱ�׼���
#include <afxext.h>         // MFC ��չ
#include <afxdisp.h>        // MFC �Զ�����

#include <afxdtctl.h>		// Internet Explorer 4 �����ؼ��� MFC ֧��
#ifndef _AFX_NO_AFXCMN_SUPPORT
#include <afxcmn.h>			// Windows �����ؼ��� MFC ֧��
#endif // _AFX_NO_AFXCMN_SUPPORT

#include <afxsock.h>		// MFC �׽�����չ
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Lmwksta.h>
#include <Lm.h>
#include <assert.h>
#include <Iphlpapi.h>
#include <pcap.h>
#pragma comment(lib,"WS2_32.LIB")
#pragma comment(lib,"Iphlpapi.LIB")
#pragma comment(lib,"Netapi32.lib")
#pragma comment (lib,"wpcap.lib")
extern CWnd * pMainWindow;
extern bool bPause;
extern bool bStop;
extern DWORD dwCurrentThreadNo;
typedef enum{NO_SCAN,ARP_SCAN,ARP_FAST_SCAN,ICMP_SCAN,ICMP_WRONG_PORT_SCAN,ICMP_IP_REORGANIZATION_SCAN,ICMP_WRONG_PROTOCOL_SCAN,TCP_CONNECT_SCAN,TCP_SYN_SCAN,TCP_FIN_SCAN,UDP_SCAN,TCP_XMAN_SCAN,TCP_NULL_SCAN} SCAN_TYPE;
#define WM_BEGIN_SCAN WM_USER+1
#define WM_HOST_SCAN_INFO WM_USER+2
#define WM_FINISH_SCAN WM_USER+3
#define WM_UPDATA_LOG WM_USER+4
#define WM_CONNECT_SCAN WM_USER+5
#define WM_CONSTRUCT_PARAM WM_USER+6
#define WM_UDP_SCAN WM_USER+7
#define WM_SYN_SCAN WM_USER+8
#define WM_FIN_SCAN WM_USER+9
#define WM_ACK_SCAN WM_USER+10
#define WM_NULL_SCAN WM_USER+11
struct ThreadParament
{
	DWORD dwOriginalIP,dwLastIP,dwOriginalPort,dwLastPort,dwTimeOut,dwTimeForOnePort,dwPacketNo;
	pcap_if_t *SelectDev;
	char HostMac[6];
	DWORD dwHostIP,dwNetMAsk,dwDefaultGateway,dwTimeBetweenToPackets;
};
