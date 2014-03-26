#include "stdafx.h"
#include "TcpConnectScan.h"
#include "DataAndConst.h"
DWORD WINAPI TcpConnectScan(LPVOID pParame)
{
	ThreadSyn cSynEntry;
	ThreadParament *pThreadParament=(ThreadParament*) pParame;
	for(DWORD dwPort=pThreadParament->dwOriginalPort;dwPort<=pThreadParament->dwLastPort&&!bStop;dwPort++)
	{
		for(DWORD dwIP=pThreadParament->dwOriginalIP;dwIP<=pThreadParament->dwLastIP&&!bStop;dwIP++)
		{
			SOCKET Socket = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP) ;
            if (Socket == INVALID_SOCKET)
			{
				pMainWindow->MessageBox("Generate Socket Error!","Eror",MB_OK|MB_ICONERROR);
				continue;
			}
			if (SOCKET_ERROR == WSAAsyncSelect (Socket, pMainWindow->m_hWnd, WM_CONNECT_SCAN, FD_CONNECT))
            {
				pMainWindow->MessageBox("WSAAsyncSelect Socket Error!","Eror",MB_OK|MB_ICONERROR);
				continue;
			}
			sockaddr_in sa;
			sa.sin_family           = AF_INET ;

            sa.sin_port             = htons((WORD)dwPort) ; 
            sa.sin_addr.S_un.S_addr = htonl(dwIP) ;

			connect(Socket, (SOCKADDR *) &sa, sizeof (sa)) ;
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
	pMainWindow->SendMessage(WM_FINISH_SCAN);
	return 0;
}