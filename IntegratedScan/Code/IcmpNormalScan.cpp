#include "Stdafx.h"
#include "IcmpNormalScan.h"
#include "DataAndConst.h"
typedef void * (__stdcall *PIcmpCreateFile)(void);
typedef void * (__stdcall *PIcmpCloseHandle)(HANDLE IcmpHandle);
typedef unsigned long (__stdcall *PIcmpSendEcho2)(HANDLE IcmpHandle,HANDLE Event,  FARPROC ApcRoutine,  PVOID ApcContext, IPAddr DestinationAddress,  LPVOID RequestData, WORD RequestSize,  PIP_OPTION_INFORMATION RequestOptions,  LPVOID ReplyBuffer, DWORD ReplySize,  DWORD Timeout);

struct ApcParament
{	
	CHAR Buffer[512];
	DWORD dwDestIP;
};


void ApcFunc(void *p)
{
	if(bStop==false)
	{	
		ApcParament * pApcParament=(ApcParament*)p;
		ICMP_ECHO_REPLY* P_Icmp_Echo_Option=(ICMP_ECHO_REPLY*)(pApcParament->Buffer);

		if(P_Icmp_Echo_Option->RoundTripTime<100000&&P_Icmp_Echo_Option->Address==htonl(pApcParament->dwDestIP))
		{
			pMainWindow->PostMessage(WM_HOST_SCAN_INFO,1,pApcParament->dwDestIP);
		}
	}
}

DWORD WINAPI IcmpNormalScan(LPVOID pThreapParam)
{
	ThreadSyn cSynEntry;
	ThreadParament *pThreadParament=(ThreadParament *)pThreapParam;
	ApcParament *ReplyBuffer=NULL;
	HMODULE hInst=LoadLibrary("iphlpapi.dll");
	if(!hInst)
	{
		return -1;
	}
		//依次获得所需的三个函数指针
	PIcmpCreateFile IcmpCreateFile=(PIcmpCreateFile)GetProcAddress(hInst,"IcmpCreateFile");
	PIcmpSendEcho2 IcmpSendEcho2=(PIcmpSendEcho2)GetProcAddress(hInst,"IcmpSendEcho2");
	PIcmpCloseHandle IcmpCloseHandle=(PIcmpCloseHandle)GetProcAddress(hInst,"IcmpCloseHandle");
	
	
	
	if(IcmpCreateFile==NULL||IcmpSendEcho2==NULL||IcmpCloseHandle==NULL)
	{
		return -1;
	}
	HANDLE IcmpHandle=0;
	IcmpHandle=IcmpCreateFile();//打开ICMP句柄 
	if(IcmpHandle==0)
	{
		return -1;
	}
	else
	{
			
		IP_OPTION_INFORMATION IpOption;//该结构用来控制所发ICMP数据包的IP头的相应字段值 
		IpOption.Flags=0;
		IpOption.OptionsData=NULL;
		IpOption.OptionsSize=0;
		IpOption.Tos=0;
		IpOption.Ttl=123;
		char *SendData = "DF is the best!"; 
		int NumberOfIP=pThreadParament->dwLastIP-pThreadParament->dwOriginalIP+1;
		ReplyBuffer=new  ApcParament[NumberOfIP];
		int i=0;
		for(DWORD dwIP=pThreadParament->dwOriginalIP;dwIP<=pThreadParament->dwLastIP&&!bStop;dwIP++,i++)
		{
			ReplyBuffer[i].dwDestIP=dwIP;
			int Res=0;
			Res=IcmpSendEcho2(IcmpHandle,
							NULL,
							(FARPROC)&ApcFunc,
							(void*)(&ReplyBuffer[i]),
							htonl(dwIP),
							SendData,
							(WORD)strlen(SendData),
							&IpOption,
							ReplyBuffer[i].Buffer,
							512,
							pThreadParament->dwTimeOut*1000);
			char  strLog[256];
			in_addr tmp;
			tmp.S_un.S_addr=htonl(dwIP);
			sprintf(strLog,"Scaning Host %s.",inet_ntoa(tmp));
			pMainWindow->SendMessage(WM_UPDATA_LOG,(WPARAM)strLog);

			SleepEx(1,true);
			while(bPause)
			{
				Sleep(100);
			}
		}//end of while
	}
	int i=0;
	while(bStop==false )
	{
		if(SleepEx(100,true)==WAIT_IO_COMPLETION)
		{
		}
		else
		{
			i++;
		}
		if(	pThreadParament->dwTimeOut*10==i)
		{
			break;
		}
		if(i%10==0)
		{
			char  strLog[256];
			sprintf(strLog,"Waiting for timeout,Last %u Seconds.\n",((pThreadParament->dwTimeOut)-(i/10)));
			pMainWindow->SendMessage(WM_UPDATA_LOG,(WPARAM)strLog);
		
		}
	}
	IcmpCloseHandle(IcmpHandle);
	pMainWindow->PostMessage(WM_FINISH_SCAN);
	delete []ReplyBuffer;
	return 0;
}