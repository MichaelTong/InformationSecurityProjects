#include "IcmpAdvencedScan.h"
#include "stdafx.h"
#include "DataAndConst.h"
bool bIcmpSending=true;
DWORD WINAPI IcmpReceiver(LPVOID pParament)
{
	ThreadSyn cSynEntry;
	pcap_if_t *pSelectDev;
	const ThreadParament * pThreadParament=(ThreadParament *)pParament;
	pSelectDev=pThreadParament->SelectDev;
	pcap_t *fp;
	pcap_pkthdr *mHeader;
	u_char *pPacketData;
	char error[256];
	ULONG dwNetMask=pThreadParament->dwNetMAsk;;;
	bpf_program fcode;
	if ( (fp= pcap_open_live(pSelectDev->name, 65536, 1, 1000, error) ) == NULL)
    {
        return 0;
    }
    int nRes=-1;
	int nTime=0;
	
	char strFilter[300];
	UCHAR *pIPAddr=(UCHAR*)&(pThreadParament->dwHostIP);
	sprintf(strFilter,"(icmp and ((ip[12]*%u+ip[13]*%u+ip[14]*%u+ip[15])>=%u) and ((ip[12]*%u+ip[13]*%u+ip[14]*%u+ip[15])<=%u) )",0x1000000,0x10000,0x100,pThreadParament->dwOriginalIP,0x1000000,0x10000,0x100,pThreadParament->dwLastIP);
	if (pcap_compile(fp, &fcode,strFilter, 1,dwNetMask) <0 )
	{
		CString Err;
		Err.Format("Can't Compile Fliter:%s",strFilter);
		MessageBox(NULL,Err,"Error",MB_OK|MB_ICONERROR);
		return 0;
	}
	if (pcap_setfilter(fp, &fcode)<0)
	{
		MessageBox(NULL,"Can't Set Fliter","Error",MB_OK|MB_ICONERROR);
		return 0;
	}

    while((nRes = pcap_next_ex( fp, &mHeader, (const u_char **)(&pPacketData))) >= 0)
	{
        
        if(nRes == 0)
		{
			
			if(bIcmpSending==false)
			{
				char  strLog[256];
				sprintf(strLog,"Waiting for timeout,Last %u Seconds.\n",((pThreadParament->dwTimeOut)-nTime));
				pMainWindow->SendMessage(WM_UPDATA_LOG,(WPARAM)strLog);
				nTime++;
			
				if(nTime==pThreadParament->dwTimeOut)
				{
					Sleep(500);
					pMainWindow->PostMessage(WM_FINISH_SCAN);
					return 0;
				}
			}
		}
		else
		{
			if(nRes == 1)
			{
				pMainWindow->PostMessage(WM_HOST_SCAN_INFO,1,ntohl(((IpPacket*)pPacketData)->theIpHead.dwSourceAddr));
		
			}
		}
		while(bPause)
		{
			Sleep(100);
		}
		if(bStop)
		{
			return 0;
		}
       
    }

	return 0;
}

DWORD WINAPI IcmpWrongPortScan (LPVOID pPar)
{
	ThreadSyn cSynEntry;
	SetBoolTrue cSBT(&bIcmpSending);
	DWORD dwThreadId;
	CreateThread(NULL,0,IcmpReceiver,pPar,0,&dwThreadId);;

	pcap_if_t *pSelectDev;
	ThreadParament * pThreadParament=(ThreadParament *)pPar;
	pSelectDev=pThreadParament->SelectDev;
	pcap_t *fp;
	char error[256];
	char bDestMac[6];
	memset(bDestMac,0xff,6);

	UdpPacket thePacket;

	DWORD dwNetMask=pThreadParament->dwNetMAsk;
	DWORD dwDefaultGatewayIp=pThreadParament->dwDefaultGateway;
	ULONG bGatewayMac[2];
	ULONG ulLen=6;
	SendARP (htonl(dwDefaultGatewayIp), 0, bGatewayMac, &ulLen);
	memcpy(thePacket.theEthHead.bDestMac,bGatewayMac,6);
	memcpy(thePacket.theEthHead.bSourceMac,pThreadParament->HostMac,6);
	thePacket.theEthHead.usEthernetType=0x8;
	thePacket.theIpHead.ucVersionAndHeadLength=0x45;
	thePacket.theIpHead.ucTos=0;
	thePacket.theIpHead.usTotalLength=htons(30);
	thePacket.theIpHead.usIdentification=1234;
	thePacket.theIpHead.usFlagsAndFragmentOffset=0;
	thePacket.theIpHead.ucTtl=119;
	thePacket.theIpHead.ucProtocol=17;//udp
	thePacket.theIpHead.dwSourceAddr=htonl(pThreadParament->dwHostIP);
	
	thePacket.theUdpHead.usSourcePort=ntohs(12345);
	thePacket.theUdpHead.usDestPort=ntohs(567);
	thePacket.theUdpHead.usLength=ntohs(10);
	thePacket.theUdpHead.usData=0x6664;


	UdpFakeHeader theFakeHeader;
	theFakeHeader.bZero=0;
	theFakeHeader.bUdpLength=htons(sizeof(UdpHead));
	theFakeHeader.bProtocolType=17;
	theFakeHeader.dwSourceAddr=htonl(pThreadParament->dwHostIP);
	
	if((fp = pcap_open_live(pSelectDev->name, 65536, 1, 1000, error) ) == NULL)
	{
		return 0;
	}
	for(DWORD dwIP=pThreadParament->dwOriginalIP;dwIP<=pThreadParament->dwLastIP&&!bStop;dwIP++)
	{
		char  strLog[256];
		in_addr tmp;
		tmp.S_un.S_addr=htonl(dwIP);
		sprintf(strLog,"Scaning Host %s.",inet_ntoa(tmp));
		pMainWindow->SendMessage(WM_UPDATA_LOG,(WPARAM)strLog);
		if((dwIP&dwNetMask)==(dwDefaultGatewayIp&dwNetMask))
		{
			ulLen=6;
			ULONG bHostMac[2];
			
			if(SendARP(htonl(dwIP),0,bHostMac,&ulLen)!=NO_ERROR)
			{
				continue;
			}
			memcpy(thePacket.theEthHead.bDestMac,bHostMac,6);

		}
		thePacket.theIpHead.dwDestAddr=htonl(dwIP);
		
		thePacket.theIpHead.usCrc=0;
		thePacket.theIpHead.usCrc=CheckSum((USHORT*)(&(thePacket.theIpHead)),sizeof(IpHead));
		
		thePacket.theUdpHead.usCrc=0;
		theFakeHeader.dwDestAddr=htonl(dwIP);
		thePacket.theUdpHead.usCrc=UdpCheckSum((char *)&(thePacket.theUdpHead),(char *)&theFakeHeader,sizeof(UdpHead));

		if(pcap_sendpacket(fp,(u_char *)(&thePacket),sizeof(thePacket))!=0)
		{
			pMainWindow->MessageBox("Send Data Error!");
		}
		while(bPause)
		{
			Sleep(100);
		}

	}
	return 0;
}

DWORD WINAPI IcmpWrongProtocolScan (LPVOID pPar)
{
	ThreadSyn cSynEntry;
	SetBoolTrue cSBT(&bIcmpSending);
	DWORD dwThreadId;
	CreateThread(NULL,0,IcmpReceiver,pPar,0,&dwThreadId);;

	pcap_if_t *pSelectDev;
	ThreadParament * pThreadParament=(ThreadParament *)pPar;
	pSelectDev=pThreadParament->SelectDev;
	pcap_t *fp;
	char error[256];
	char bDestMac[6];
	memset(bDestMac,0xff,6);

	IpPacket thePacket;

	DWORD dwNetMask=pThreadParament->dwNetMAsk;
	DWORD dwDefaultGatewayIp=pThreadParament->dwDefaultGateway;
	ULONG bGatewayMac[2];
	ULONG ulLen=6;
	SendARP (htonl(dwDefaultGatewayIp), 0, bGatewayMac, &ulLen);
	memcpy(thePacket.theEthHead.bDestMac,bGatewayMac,6);
	memcpy(thePacket.theEthHead.bSourceMac,pThreadParament->HostMac,6);
	thePacket.theEthHead.usEthernetType=0x8;
	thePacket.theIpHead.ucVersionAndHeadLength=0x45;
	thePacket.theIpHead.ucTos=0;
	thePacket.theIpHead.usTotalLength=htons(20);
	thePacket.theIpHead.usIdentification=1234;
	thePacket.theIpHead.usFlagsAndFragmentOffset=12345;
	thePacket.theIpHead.ucTtl=102;
	thePacket.theIpHead.ucProtocol=250;
	thePacket.theIpHead.dwSourceAddr=htonl(pThreadParament->dwHostIP);
	
	
	if((fp = pcap_open_live(pSelectDev->name, 65536, 1, 1000, error) ) == NULL)
	{
		return 0;
	}
	for(DWORD dwIP=pThreadParament->dwOriginalIP;dwIP<=pThreadParament->dwLastIP&&!bStop;dwIP++)
	{
		char  strLog[256];
		in_addr tmp;
		tmp.S_un.S_addr=htonl(dwIP);
		sprintf(strLog,"Scaning Host %s.",inet_ntoa(tmp));
		pMainWindow->SendMessage(WM_UPDATA_LOG,(WPARAM)strLog);
		if((dwIP&dwNetMask)==(dwDefaultGatewayIp&dwNetMask))
		{
			ulLen=6;
			ULONG bHostMac[2];
			
			if(SendARP(htonl(dwIP),0,bHostMac,&ulLen)!=NO_ERROR)
			{
				continue;
			}
			memcpy(thePacket.theEthHead.bDestMac,bHostMac,6);

		}
		thePacket.theIpHead.dwDestAddr=htonl(dwIP);
		
		thePacket.theIpHead.usCrc=0;
		thePacket.theIpHead.usCrc=CheckSum((USHORT*)(&(thePacket.theIpHead)),sizeof(IpHead));

		if(pcap_sendpacket(fp,(u_char *)(&thePacket),sizeof(IpPacket))!=0)
		{
			pMainWindow->MessageBox("Send Data Error!");
		}
		while(bPause)
		{
			Sleep(100);
		}

	}
	return 0;
}
DWORD WINAPI IcmpErrorReorganizationScan (LPVOID pPar)
{
	ThreadSyn cSynEntry;
	SetBoolTrue cSBT(&bIcmpSending);
	DWORD dwThreadId;
	CreateThread(NULL,0,IcmpReceiver,pPar,0,&dwThreadId);;

	pcap_if_t *pSelectDev;
	ThreadParament * pThreadParament=(ThreadParament *)pPar;
	pSelectDev=pThreadParament->SelectDev;
	pcap_t *fp;
	char error[256];
	char bDestMac[6];
	memset(bDestMac,0xff,6);

	///UdpPacket thePacket;

	char bBuffer[1500+sizeof(EthernetHead)];
	memset(bBuffer,8,sizeof(bBuffer));
	UdpPacket *pPacket=(UdpPacket *)bBuffer;

	DWORD dwNetMask=pThreadParament->dwNetMAsk;
	DWORD dwDefaultGatewayIp=pThreadParament->dwDefaultGateway;
	ULONG bGatewayMac[2];
	ULONG ulLen=6;
	SendARP (htonl(dwDefaultGatewayIp), 0, bGatewayMac, &ulLen);
	memcpy(pPacket->theEthHead.bDestMac,bGatewayMac,6);
	memcpy(pPacket->theEthHead.bSourceMac,pThreadParament->HostMac,6);
	pPacket->theEthHead.usEthernetType=0x8;
	pPacket->theIpHead.ucVersionAndHeadLength=0x45;
	pPacket->theIpHead.ucTos=0;
	pPacket->theIpHead.usTotalLength=htons(1500);
	pPacket->theIpHead.usIdentification=1234;
	pPacket->theIpHead.usFlagsAndFragmentOffset=0x20;
	pPacket->theIpHead.ucTtl=99;
	pPacket->theIpHead.ucProtocol=17;//udp
	pPacket->theIpHead.dwSourceAddr=htonl(pThreadParament->dwHostIP);
	
	pPacket->theUdpHead.usSourcePort=ntohs(12345);
	pPacket->theUdpHead.usDestPort=ntohs(445);
	pPacket->theUdpHead.usLength=ntohs(2000);
	pPacket->theUdpHead.usData=0x6664;


	UdpFakeHeader theFakeHeader;
	theFakeHeader.bZero=0;
	theFakeHeader.bUdpLength=htons(2000);
	theFakeHeader.bProtocolType=17;
	theFakeHeader.dwSourceAddr=htonl(pThreadParament->dwHostIP);

	if((fp = pcap_open_live(pSelectDev->name, 65536, 1, 1000, error) ) == NULL)
	{
		return 0;
	}
	for(DWORD dwIP=pThreadParament->dwOriginalIP;dwIP<=pThreadParament->dwLastIP&&!bStop;dwIP++)
	{
		char  strLog[256];
		in_addr tmp;
		tmp.S_un.S_addr=htonl(dwIP);
		sprintf(strLog,"Scaning Host %s.",inet_ntoa(tmp));
		pMainWindow->SendMessage(WM_UPDATA_LOG,(WPARAM)strLog);
		if((dwIP&dwNetMask)==(dwDefaultGatewayIp&dwNetMask))
		{
			ulLen=6;
			ULONG bHostMac[2];
			
			if(SendARP(htonl(dwIP),0,bHostMac,&ulLen)!=NO_ERROR)
			{
				continue;
			}
			memcpy(pPacket->theEthHead.bDestMac,bHostMac,6);

		}
		pPacket->theIpHead.dwDestAddr=htonl(dwIP);
		
		pPacket->theIpHead.usCrc=0;
		pPacket->theIpHead.usCrc=CheckSum((USHORT*)(&(pPacket->theIpHead)),sizeof(IpHead));
		
		pPacket->theUdpHead.usCrc=0;
		theFakeHeader.dwDestAddr=htonl(dwIP);
		pPacket->theUdpHead.usCrc=UdpCheckSum((char *)&(pPacket->theUdpHead),(char *)&theFakeHeader,1480);

		if(pcap_sendpacket(fp,(u_char *)(bBuffer),sizeof(bBuffer))!=0)
		{
			pMainWindow->MessageBox("Send Data Error!");
		}
		while(bPause)
		{
			Sleep(100);
		}

	}
	return 0;
}