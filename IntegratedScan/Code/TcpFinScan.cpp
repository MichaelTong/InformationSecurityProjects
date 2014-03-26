#include "StdAfx.h"
#include ".\tcpfinscan.h"
#include "DataAndConst.h"
bool bFinSending= true;
DWORD WINAPI TcpRstReceiverFin(LPVOID pParament)
{
	ThreadSyn cSynEntry;
	pcap_if_t *pSelectDev;
	const ThreadParament * pThreadParament=(ThreadParament *)pParament;
	pSelectDev=pThreadParament->SelectDev;
	pcap_t *fp;
	pcap_pkthdr *mHeader;
	u_char *pPacketData;
	char error[256];
	ULONG dwNetMask=pThreadParament->dwNetMAsk;
	bpf_program fcode;
	if ( (fp= pcap_open_live(pSelectDev->name, 65536, 0, 1000, error) ) == NULL)
    {
        return 0;
    }
    int nRes=-1;
	int nTime=0;

	char strFilter[300];
	UCHAR *pIPAddr=(UCHAR*)&(pThreadParament->dwHostIP);//and (tcp[8:4]=%u) and (dst port 12345),ntohl(198328)
	sprintf(strFilter,"(tcp and (tcp[tcpflags] & (tcp-rst) != 0) and ((ip[12]*%u+ip[13]*%u+ip[14]*%u+ip[15])>=%u) and ((ip[12]*%u+ip[13]*%u+ip[14]*%u+ip[15])<=%u) )",0x1000000,0x10000,0x100,pThreadParament->dwOriginalIP,0x1000000,0x10000,0x100,pThreadParament->dwLastIP);
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
			if(	bFinSending==false)
			{
				char  strLog[256];
				sprintf(strLog,"Waiting for timeout,Last %u Seconds.\n",((pThreadParament->dwTimeOut)-nTime));
				pMainWindow->SendMessage(WM_UPDATA_LOG,(WPARAM)strLog);
				nTime++;
			}
			if(nTime==pThreadParament->dwTimeOut)
			{
				Sleep(500);
				pMainWindow->PostMessage(WM_FINISH_SCAN);
				return 0;
			}
		}
		else
		{
			nTime=0;
			if(nRes == 1)
			{

				DWORD dwIp=ntohl(((IpPacket*)pPacketData)->theIpHead.dwSourceAddr);
				WORD dSourcePort=ntohs(((TcpPacket*)pPacketData)->theTcpHead.usSourcePort);
				WORD dDestPort=ntohs(((TcpPacket*)pPacketData)->theTcpHead.usDestPort);
				if(dSourcePort>=pThreadParament->dwOriginalPort&&dSourcePort<=pThreadParament->dwLastPort)
				{
					if(dDestPort==12345)
					{
						DWORD dwStateAndPort=dSourcePort;

						pMainWindow->PostMessage(WM_FIN_SCAN,dwStateAndPort,dwIp);
					}
				}
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

DWORD WINAPI TcpFinScan(LPVOID pPar)
{
	ThreadSyn cSynEntry;
	SetBoolTrue cSBT(&bFinSending);
	DWORD dwThreadId;
	CreateThread(NULL,0,TcpRstReceiverFin,pPar,0,&dwThreadId);
	
	pcap_if_t *pSelectDev;
	ThreadParament * pThreadParament=(ThreadParament *)pPar;
	pSelectDev=pThreadParament->SelectDev;
	pcap_t *fp;
	char error[256];
	char bDestMac[6];
	memset(bDestMac,0xff,6);

	TcpPacket thePacket;

	DWORD dwNetMask=pThreadParament->dwNetMAsk;
	DWORD dwDefaultGatewayIp=pThreadParament->dwDefaultGateway;
	ULONG bGatewayMac[2];
	ULONG ulLen=6;
	if(SendARP(htonl(dwDefaultGatewayIp),0,bGatewayMac,&ulLen)!=NO_ERROR)
	{	
		return 0;
	}
	memcpy(thePacket.theIpPacket.theEthHead.bDestMac,bGatewayMac,6);
	memcpy(thePacket.theIpPacket.theEthHead.bSourceMac,pThreadParament->HostMac,6);
	thePacket.theIpPacket.theEthHead.usEthernetType=0x8;
	thePacket.theIpPacket.theIpHead.ucVersionAndHeadLength=0x45;
	thePacket.theIpPacket.theIpHead.ucTos=0;
	thePacket.theIpPacket.theIpHead.usTotalLength=htons(48);;
	thePacket.theIpPacket.theIpHead.usIdentification=1234;
	thePacket.theIpPacket.theIpHead.usFlagsAndFragmentOffset=0;
	thePacket.theIpPacket.theIpHead.ucTtl=119;
	thePacket.theIpPacket.theIpHead.ucProtocol=6;//tcp
	thePacket.theIpPacket.theIpHead.dwSourceAddr=htonl(pThreadParament->dwHostIP);
	
	thePacket.theTcpHead.usSourcePort=htons(12345);
	thePacket.theTcpHead.dwSeq=ntohl(198327);
	thePacket.theTcpHead.dwAck=0;
	thePacket.theTcpHead.ucLength=0x70;
	thePacket.theTcpHead.ucFlag=1;
	thePacket.theTcpHead.usWindow=0xFFFF;	 //16 位窗口大小
	thePacket.theTcpHead.usCrc=0;//16 位校验和
	thePacket.theTcpHead.usUrgent=0;//16 位紧急数据偏移量
	thePacket.theTcpHead.unMssOpt=htonl(0x020405B4);
	thePacket.theTcpHead.usNopOpt= 0x0101;
	thePacket.theTcpHead.usSackOpt= 0x0204;

	TcpFakeHeader theFakeHeader;
	theFakeHeader.bZero=0;
	theFakeHeader.bTcpLength=htons(28);
	theFakeHeader.bProtocolType=6;
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
			memcpy(thePacket.theIpPacket.theEthHead.bDestMac,bHostMac,6);

		}
		thePacket.theIpPacket.theIpHead.dwDestAddr=htonl(dwIP);
		
		for(DWORD dwPort=pThreadParament->dwOriginalPort;dwPort<=pThreadParament->dwLastPort&&!bStop;dwPort++)
		{
			thePacket.theTcpHead.usDestPort=htons((WORD)dwPort);
			thePacket.theIpPacket.theIpHead.usCrc=0;
			thePacket.theIpPacket.theIpHead.usCrc=CheckSum((const char *)(&(thePacket.theIpPacket.theIpHead)),sizeof(IpHead));
			thePacket.theTcpHead.usCrc=0;
			theFakeHeader.dwDestAddr=htonl(dwIP);
			thePacket.theTcpHead.usCrc=TcpCheckSum((char *)&(thePacket.theTcpHead),(char *)&(theFakeHeader),28);
		
			if(pcap_sendpacket(fp,(u_char *)(&thePacket),sizeof(TcpPacket))!=0)
			{
				pMainWindow->MessageBox("Send Data Error!");
			}
			while(bPause)
			{
				Sleep(100);
			}
		}
	}
	return 0;
}