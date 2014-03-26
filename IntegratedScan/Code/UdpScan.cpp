#include "stdafx.h"
#include "UdpScan.h"
#include "DataAndConst.h"
struct SocketInfo
{
	WSAOVERLAPPED Overlapped;
	SOCKET Socket;
	DWORD dwIp;
	WORD wPort;
	DWORD dwSleepTime;
};
void CALLBACK CompletionROUTINE(
								IN DWORD dwError,
								IN DWORD cbTransferred,
								IN LPWSAOVERLAPPED lpOverlapped,
								IN DWORD dwFlags)
{
	while(bPause)
	{
		Sleep(100);
	}
	if(bStop)
	{
		return;
	}
	SocketInfo *pSocketInfo=(SocketInfo*)lpOverlapped;
	sockaddr_in sa;
	sa.sin_family           = AF_INET ;
    sa.sin_port             = htons(pSocketInfo->wPort) ; 
	sa.sin_addr.S_un.S_addr = htonl(pSocketInfo->dwIp) ;
	DWORD dwByteRecv,dwFlag=0;
	DWORD dwErrorCode=0;
	int nSize=sizeof(sa);
	WSABUF RecvBuf;
	char chBuf[2];
	RecvBuf.buf=chBuf;
	RecvBuf.len=2;
	SleepEx(pSocketInfo->dwSleepTime,TRUE);
	
	int nRes=WSARecvFrom(pSocketInfo->Socket,&RecvBuf,1,&dwByteRecv,&dwFlag,(sockaddr *)&sa,&nSize,&(pSocketInfo->Overlapped),NULL);
	{
		if (nRes!=0)
		{
			dwErrorCode=WSAGetLastError();
		}
	}
	if(dwErrorCode==10054)//port Closed
	{
		DWORD dwLparam=pSocketInfo->wPort;
		pMainWindow->SendMessage(WM_UDP_SCAN,pSocketInfo->dwIp,dwLparam);
	}
	else//port open
	{
		DWORD dwLparam=pSocketInfo->wPort+0xffff0000;
		pMainWindow->SendMessage(WM_UDP_SCAN,pSocketInfo->dwIp,dwLparam);
	}
	WSACloseEvent(pSocketInfo->Overlapped.hEvent);
	closesocket(pSocketInfo->Socket);
	delete pSocketInfo;
}

DWORD WINAPI UdpScan(LPVOID pPara)
{
	ThreadSyn cSynEntry;
	ThreadParament *pThreadParament=(ThreadParament*) pPara;
	int nSendTimes=0;
	for(DWORD dwPort=pThreadParament->dwOriginalPort;dwPort<=pThreadParament->dwLastPort&&!bStop;dwPort++)
	{
		for(DWORD dwIP=pThreadParament->dwOriginalIP;dwIP<=pThreadParament->dwLastIP&&!bStop;dwIP++)
		{
			SOCKET Socket = WSASocket(AF_INET, SOCK_DGRAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
            if (Socket == INVALID_SOCKET)
			{
				pMainWindow->MessageBox("Generate Socket Error!","Eror",MB_OK|MB_ICONERROR);
				continue;
			}
			sockaddr_in sa;
			sa.sin_family           = AF_INET ;
            sa.sin_port             = htons((WORD)dwPort) ; 
            sa.sin_addr.S_un.S_addr = htonl(dwIP) ;
			WSABUF SendBuf;
			char buf[2];
			buf[0]='d';
			buf[1]='f';
			SendBuf.buf=buf;
			SendBuf.len=2;
			DWORD dwByteSend,dwFlag=0;
			DWORD dwErrorCode=0;
			int nSize=sizeof(sa);
			SocketInfo *pSocketInfo=new SocketInfo;
			pSocketInfo->Overlapped.hEvent=WSACreateEvent();
			pSocketInfo->Overlapped.Internal		= 0;
			pSocketInfo->Overlapped.InternalHigh = 0;
			pSocketInfo->Overlapped.Offset		= 0;
			pSocketInfo->Overlapped.OffsetHigh	= 0;
			pSocketInfo->dwIp=dwIP;
			pSocketInfo->wPort=(WORD)dwPort;
			pSocketInfo->Socket=Socket;
			pSocketInfo->dwSleepTime=pThreadParament->dwTimeForOnePort;
			
			if(0!=WSASendTo(Socket,&SendBuf,1,&dwByteSend,dwFlag,(sockaddr*)&sa,nSize,&pSocketInfo->Overlapped,CompletionROUTINE))
			{
				dwErrorCode=WSAGetLastError();
				if(dwErrorCode==ERROR_IO_PENDING)
				{
					nSendTimes++;
					if(nSendTimes==5)
					{
						SleepEx(0,TRUE);
						nSendTimes=0;
					}
				}
				if(pThreadParament->dwTimeBetweenToPackets!=0)
				{
					Sleep(pThreadParament->dwTimeBetweenToPackets);
				}
			}
			char  strLog[256];
			in_addr tmp;
			tmp.S_un.S_addr=sa.sin_addr.S_un.S_addr;
			sprintf(strLog,"Scaning Host %s, Port %u\n",inet_ntoa(tmp),dwPort);
			pMainWindow->SendMessage(WM_UPDATA_LOG,(WPARAM)strLog);
			while(bPause)
			{
				Sleep(100);
			}
		}
	}
	for(DWORD i=0;i<10*(pThreadParament->dwTimeOut);)
	{
		if(i%10==9)
		{
			char  strLog[256];
			sprintf(strLog,"Waiting for timeout,Last %u Seconds.\n",((pThreadParament->dwTimeOut)-(i/10)));
			pMainWindow->SendMessage(WM_UPDATA_LOG,(WPARAM)strLog);
		}
		if(SleepEx(100,TRUE)==0)
		{
			i++;
		}
		if(bStop)
		{
			break;
		}
	}
	pMainWindow->SendMessage(WM_FINISH_SCAN);
	return 0;
}
