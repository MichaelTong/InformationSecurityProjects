#include "Stdafx.h"

#include "ArpSlowScan.h"
#include "DataAndConst.h"
DWORD WINAPI ArpSlowScan(LPVOID pParament)
{
	ThreadSyn cSynEntry;
	ThreadParament *pThreadParament=(ThreadParament *)pParament;
	//pMainWindow->MessageBox("Arp Slow Scan");
	for(DWORD dwIP=pThreadParament->dwOriginalIP;dwIP<=pThreadParament->dwLastIP&&!bStop;dwIP++)
	{
		IPAddr  ipAddr;
		ULONG   pulMac[2];
		ULONG   ulLen;

		ipAddr=htonl(dwIP);
		memset (pulMac, 0xff, sizeof (pulMac));
		ulLen = 6;
	    
		if(SendARP (ipAddr, 0, pulMac, &ulLen)==NO_ERROR)
		{
			pMainWindow->PostMessage(WM_HOST_SCAN_INFO,0,dwIP);
		}
		while(bPause)
		{
			Sleep(100);
		}
		char  strLog[256];
		in_addr tmp;
		tmp.S_un.S_addr=ipAddr;
		sprintf(strLog,"Scaning Host %s\n",inet_ntoa(tmp));
		pMainWindow->SendMessage(WM_UPDATA_LOG,(WPARAM)strLog);
	}
	pMainWindow->PostMessage(WM_FINISH_SCAN);
	return 0;
}