
#include "stdafx.h"
#include "ScanHandler.h"
#include "ArpSlowScan.h"
#include "IcmpNormalScan.h"
#include "TcpConnectScan.h"
#include "UdpScan.h"
#include "ArpFastScan.h"
#include "IcmpAdvencedScan.h"
#include "TcpSynScan.h"
#include "TcpFinScan.h"
#include "TcpNullScan.h"
#include "TcpAckScan.h"
void ScanHandler(SCAN_TYPE enScanType,ThreadParament * pThreadParament)
{
	DWORD ThreadID=0;
	switch (enScanType)
	{
	case ARP_SCAN:
		{
			CreateThread(NULL,0,ArpSlowScan,pThreadParament,0,&ThreadID);
			break;
		}
	case ARP_FAST_SCAN:
		{
			CreateThread(NULL,0,ArpFastScan,pThreadParament,0,&ThreadID);
			break;
		}
	case ICMP_SCAN:
		{
			CreateThread(NULL,0,IcmpNormalScan,pThreadParament,0,&ThreadID);
			break;
		}
	case ICMP_WRONG_PORT_SCAN:
		{
			CreateThread(NULL,0,IcmpWrongPortScan,pThreadParament,0,&ThreadID);
			break;
		}
	case ICMP_IP_REORGANIZATION_SCAN:
		{
			CreateThread(NULL,0,IcmpErrorReorganizationScan,pThreadParament,0,&ThreadID);
			break;
		}

	case ICMP_WRONG_PROTOCOL_SCAN:
		{
			CreateThread(NULL,0,IcmpWrongProtocolScan,pThreadParament,0,&ThreadID);
			break;
		}
	case TCP_CONNECT_SCAN:
		{
			CreateThread(NULL,0,TcpConnectScan,pThreadParament,0,&ThreadID);
			break;
		}
	case TCP_SYN_SCAN:
		{
			CreateThread(NULL,0,TcpSynScan,pThreadParament,0,&ThreadID);
			break;
		}
	case TCP_FIN_SCAN:
		{
			CreateThread(NULL,0,TcpFinScan,pThreadParament,0,&ThreadID);
			break;
		}
	case TCP_XMAN_SCAN:
		{
			CreateThread(NULL,0,TcpAckScan,pThreadParament,0,&ThreadID);
			break;
		}
	case TCP_NULL_SCAN:
		{
			CreateThread(NULL,0,TcpNullScan,pThreadParament,0,&ThreadID);
			break;
		}
	case UDP_SCAN:
		{
			CreateThread(NULL,0,UdpScan,pThreadParament,0,&ThreadID);
			break;
		}
	default:
		{
			break;
		}
	};
		
}