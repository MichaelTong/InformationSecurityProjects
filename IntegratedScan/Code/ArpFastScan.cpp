#include "StdAfx.h"
#include ".\arpfastscan.h"
#include "DataAndConst.h"

class Arp_Packet
{
public:
	void set_arp_option(unsigned short usOpetion)
	{
		this->arppac->theArpHead.usOpetion=htons(usOpetion);
	}
	void fill_arp_source_ip(u_long sour)
	{
		this->arppac->theArpHead.dwSourecIP=htonl(sour);
	}

	void fill_arp_dest_ip(u_long dest)
	{
		this->arppac->theArpHead.dwDestIP=htonl(dest);
	}

	void fill_arp_dest_mac(void * dest)
	{
		memcpy((void*)(this->arppac->theArpHead.DestMac),(const void* )dest,6);
	}
	void fill_arp_source_mac(void * source)
	{
		memcpy((void*)(this->arppac->theArpHead.SourceMac),(const void* )source,6);
	}
	void fill_eth_source(void * source)
	{
		memcpy((void*) (this->arppac->theEthernetHead.bSourceMac),(const void*)source,6);
	}
	void fill_eth_dest(void * dest)
	{
		memcpy((void*)(this->arppac->theEthernetHead.bDestMac),(const void*)dest,6);
	}
	ArpPacket *arppac;
	
	Arp_Packet()//默认包长度60
	{
		//buf=new unsigned char[60];
		this->arppac=(ArpPacket *)buf;
		for (int i=0;i<18;i++)
		{
			this->arppac->theArpHead.Padding[i]=0;
		}
		this->arppac->theEthernetHead.usEthernetType=htons(0x0806);
		this->arppac->theArpHead.usHardWareType=htons(0x1);
		this->arppac->theArpHead.usProtocolType=htons(0x0800);
		this->arppac->theArpHead.ucMacLength=6;
		this->arppac->theArpHead.ucProtocolLength=4;

	}
	
	~Arp_Packet()
	{
		//delete (this->buf);
	}
	
	
	void choose_eth_type(unsigned short type=0x0806)//默认值为0x0806
	{
		this->arppac->theEthernetHead.usEthernetType=htons(type);
	}
	void set_arp_hardware_type(u_short t=1)//默认值为1
	{
		this->arppac->theArpHead.usHardWareType=htons(t);
	}
	void set_arp_protocol_type(u_short t=0x0800)//默认值为0800
	{
		this->arppac->theArpHead.usProtocolType=htons(t);
	}
	void set_arp_hardware_len(unsigned char l=6)//默认值为6
	{
		this->arppac->theArpHead.ucMacLength=6;
	}
	void set_arp_protocol_len(unsigned char l=4)//默认值为4
	{
		this->arppac->theArpHead.ucProtocolLength=l;
	}
private:
	unsigned char buf[60];
};

DWORD WINAPI ArpFastSend(LPVOID pParament)
{
	ThreadSyn cSynEntry;
	pcap_if_t *pSelectDev;
	ThreadParament * pThreadParament=(ThreadParament *)pParament;
	pSelectDev=pThreadParament->SelectDev;
	pcap_t *fp;
	char error[256];
	char bDestMac[6];
	memset(bDestMac,0xff,6);
	Arp_Packet thePacket;
	thePacket.fill_arp_dest_mac(bDestMac);
	thePacket.fill_arp_source_mac(pThreadParament->HostMac);
	thePacket.fill_eth_dest(bDestMac);
	thePacket.fill_eth_source(pThreadParament->HostMac);
	thePacket.set_arp_option(1);
	if((fp = pcap_open_live(pSelectDev->name, 65536, 1, 1000, error) ) == NULL)
	{
		return 0;
	}
	for(DWORD dwIP=pThreadParament->dwOriginalIP;dwIP<=pThreadParament->dwLastIP&&!bStop;dwIP++)
	{
		thePacket.fill_arp_dest_ip(dwIP);
		thePacket.fill_arp_source_ip(pThreadParament->dwHostIP);
		Sleep(1);
		pcap_sendpacket(fp,(u_char *)(thePacket.arppac),60);
		while(bPause)
		{
				Sleep(100);
		}
		
	}
	return 0;
}
DWORD WINAPI ArpFastRecv(LPVOID pParament)
{
	ThreadSyn cSynEntry;
	pcap_if_t *pSelectDev;
	const ThreadParament * pThreadParament=(ThreadParament *)pParament;
	pSelectDev=pThreadParament->SelectDev;
	pcap_t *fp;
	pcap_pkthdr *mHeader;
	u_char *pPacketData;
	char error[256];
	ULONG dwNetMask=htonl(pThreadParament->dwNetMAsk);
	bpf_program fcode;
	if ( (fp= pcap_open_live(pSelectDev->name, 65536, 0, 1000, error) ) == NULL)
    {
        return 0;
    }
    int nRes=-1;
	int nTime=0;
	char strFilter[300];
	UCHAR *pIPAddr=(UCHAR*)&(pThreadParament->dwHostIP);
	sprintf(strFilter,"arp");
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
		else
		{
			if(nRes == 1)
			{
				ArpPacket* pArpPacket=(ArpPacket*)pPacketData;
				if(pArpPacket->theArpHead.usOpetion==htons(2))
				{//receive theArpHead reply packet
					pMainWindow->PostMessage(WM_HOST_SCAN_INFO,0,htonl(pArpPacket->theArpHead.dwSourecIP));
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
DWORD WINAPI ArpFastScan(LPVOID pParament)
{
	ThreadParament * pParam=(ThreadParament *)pParament;
	DWORD ThreadID=0;
	CreateThread(NULL,0,ArpFastRecv,pParament,0,&ThreadID);
	Sleep(1);
	ArpFastSend(pParament);
	return 0;
}
