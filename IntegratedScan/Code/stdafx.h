// stdafx.h : 标准系统包含文件的包含文件，
// 或是经常使用但不常更改的
// 项目特定的包含文件

#pragma once

#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN		// 从 Windows 标头中排除不常使用的资料
#endif

// 如果您必须使用下列所指定的平台之前的平台，则修改下面的定义。
// 有关不同平台的相应值的最新信息，请参考 MSDN。
#ifndef WINVER				// 允许使用 Windows 95 和 Windows NT 4 或更高版本的特定功能。
#define WINVER 0x0400		//为 Windows98 和 Windows 2000 及更新版本改变为适当的值。
#endif

#ifndef _WIN32_WINNT		// 允许使用 Windows NT 4 或更高版本的特定功能。
#define _WIN32_WINNT 0x0400		//为 Windows98 和 Windows 2000 及更新版本改变为适当的值。
#endif						

#ifndef _WIN32_WINDOWS		// 允许使用 Windows 98 或更高版本的特定功能。
#define _WIN32_WINDOWS 0x0410 //为 Windows Me 及更新版本改变为适当的值。
#endif

#ifndef _WIN32_IE			// 允许使用 IE 4.0 或更高版本的特定功能。
#define _WIN32_IE 0x0400	//为 IE 5.0 及更新版本改变为适当的值。
#endif

#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS	// 某些 CString 构造函数将是显式的

// 关闭 MFC 对某些常见但经常被安全忽略的警告消息的隐藏
#define _AFX_ALL_WARNINGS

#include <afxwin.h>         // MFC 核心和标准组件
#include <afxext.h>         // MFC 扩展
#include <afxdisp.h>        // MFC 自动化类

#include <afxdtctl.h>		// Internet Explorer 4 公共控件的 MFC 支持
#ifndef _AFX_NO_AFXCMN_SUPPORT
#include <afxcmn.h>			// Windows 公共控件的 MFC 支持
#endif // _AFX_NO_AFXCMN_SUPPORT

#include <afxsock.h>		// MFC 套接字扩展
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
