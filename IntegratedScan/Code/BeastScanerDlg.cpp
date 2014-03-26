// BeastScanerDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "BeastScaner.h"
#include "BeastScanerDlg.h"
#include ".\beastscanerdlg.h"
#include "ScanHandler.h"
#include "Choose.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CBeastScanerDlg 对话框



CBeastScanerDlg::CBeastScanerDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CBeastScanerDlg::IDD, pParent)
	, enCurrentScanType(NO_SCAN)
	, stCurrentState(_T(""))
	,dwCurrentHostNo(0)
	,dwCurrentPortInfoNo(0)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	dwLocalIP=0;
	memset(bLocalMac,0,6);
	this->enCurrentScanType=NO_SCAN;
}

void CBeastScanerDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_TAB1, cTabCtrl);

	DDX_Control(pDX, IDC_LIST_HOST_INFO, cListHostInfo);
	DDX_Control(pDX, IDC_LIST_PORT_INFO, cListPortInfo);
	DDX_Control(pDX, IDC_BUTTON1, cButtonPause);
	DDX_Text(pDX, IDC_EDIT2, stCurrentState);
}

BEGIN_MESSAGE_MAP(CBeastScanerDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_MESSAGE(WM_BEGIN_SCAN, OnBeginScan)
	ON_MESSAGE(WM_FINISH_SCAN, OnFinishScan)
	ON_MESSAGE(WM_HOST_SCAN_INFO, OnAddHostInfo)
	ON_MESSAGE(WM_UPDATA_LOG, OnUpdataLog)
	ON_MESSAGE(WM_CONNECT_SCAN,OnHandleConnectScan)
	ON_MESSAGE(WM_UDP_SCAN,OnHandleUdpScan)
	ON_MESSAGE(WM_SYN_SCAN,OnHandleSynScan)
	ON_MESSAGE(WM_FIN_SCAN,OnHandleFinScan)
	ON_MESSAGE(WM_ACK_SCAN,OnHandleAckScan)
	ON_MESSAGE(WM_NULL_SCAN,OnHandleNullScan)
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_BUTTON1, OnBnClickedPause)
	ON_BN_CLICKED(IDC_BUTTON2, OnBnClickedStop)
	//
	ON_NOTIFY(NM_DBLCLK, IDC_LIST_HOST_INFO, OnNMDblclkListHostInfo)
	ON_WM_DESTROY()
END_MESSAGE_MAP()


// CBeastScanerDlg 消息处理程序

BOOL CBeastScanerDlg::OnInitDialog()
{
	CDialog::OnInitDialog();
	pMainWindow=this;
	// 将\“关于...\”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	this->stCurrentState="Wait for user command.";
	this->GetLocalInfo();
	this->InitListCtrl();
	this->InitTabCtrl();
	this->UpdateData(FALSE);
	

	char errbuf[PCAP_ERRBUF_SIZE+1];
	
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		CString ErrInfo;
		ErrInfo.Format("Error in pcap_findalldevs: %s\n", errbuf);
		MessageBox(ErrInfo,"Error",MB_OK|MB_ICONERROR);
		exit(1);
	}
	this->SelectDev=alldevs;
	CChoose Adapter(this->alldevs,NULL);
	/* Scan the list printing every entry */
	
	if(Adapter.DoModal()==IDOK)
	{
		pcap_if_t *d=alldevs;
		for(int i=0;i<=Adapter.CurrentSel;i++)
		{
			this->SelectDev=d;
			d=d->next;
		}
		
	}
	else
	{
		exit (0);
	}
	return TRUE;  // 除非设置了控件的焦点，否则返回 TRUE
}

void CBeastScanerDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。
void CBeastScanerDlg::OnNMDblclkListHostInfo(NMHDR *pNMHDR, LRESULT *pResult)
{
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;
	if(pNMHDR->code==NM_DBLCLK)
	{
		int nCurrentSel=this->cListHostInfo.GetSelectionMark();
		if(nCurrentSel<0)
		{
			return ;
		}
		else
		{
			if(this->enCurrentScanType==NO_SCAN)
			{
				DWORD dwHostIP=ntohl(inet_addr(this->cListHostInfo.GetItemText(nCurrentSel,1).GetBuffer()));
				this->cTabCtrl.SelectTab(2);
				this->cPortScanDlg.dwOriginateIP=dwHostIP;
				this->cPortScanDlg.bSingleIP=TRUE;
				this->cPortScanDlg.UpdateData(FALSE);
				this->cPortScanDlg.cIPAddressCtrl.EnableWindow(FALSE);
			}
			else
			{
				this->MessageBox("It is scaning now,Please try latter.","Attention",MB_OK|MB_ICONSTOP);
			}
		}
	}
}

void CBeastScanerDlg::GetLocalInfo(void)
{
	char strName[64];
	PIP_ADAPTER_INFO pAdapterInfo = NULL;
	ULONG ulLen = 0;
	gethostname(strName,64);
    ::GetAdaptersInfo(pAdapterInfo,&ulLen);
	pAdapterInfo = (PIP_ADAPTER_INFO)::GlobalAlloc(GPTR, ulLen);

	// 取得本地适配器结构信息
	if(::GetAdaptersInfo(pAdapterInfo,&ulLen) ==  ERROR_SUCCESS)
	{
		if(pAdapterInfo != NULL)
		{
			memcpy(this->bLocalMac, pAdapterInfo->Address, 6);
			this->dwDefaultGateway= ntohl(::inet_addr(pAdapterInfo->GatewayList.IpAddress.String));
			this->dwLocalIP = ntohl(::inet_addr(pAdapterInfo->IpAddressList.IpAddress.String));
			this->dwNetMask= ntohl(::inet_addr(pAdapterInfo->IpAddressList.IpMask.String));
		}
		else
		{
			exit (0);
		}
	}
	else
	{
		exit (0);
	}
	
	
	this->cArpScanDlg.dwLocalIP=this->dwLocalIP;
	this->cArpScanDlg.strHostName.Format("%s",strName);
	this->cArpScanDlg.dwDefaultGateway=this->dwDefaultGateway;
	this->cArpScanDlg.dwNetMask=this->dwNetMask;

	this->cIcmpScanDlg.dwOriginateIPAddress=1+(this->dwLocalIP&0xffffff00);
	this->cIcmpScanDlg.dwLastIPAddress=254+(this->dwLocalIP&0xffffff00);

	this->cPortScanDlg.dwOriginateIP=1+(this->dwLocalIP&0xffffff00);
	this->cPortScanDlg.dwLastIP=254+(this->dwLocalIP&0xffffff00);
    
	// 为适配器结构申请内存

	memcpy(this->cArpScanDlg.bLocalMac,this->bLocalMac,6);

}

void CBeastScanerDlg::InitListCtrl(void)
{
	this->cListHostInfo.SetExtendedStyle(this->cListHostInfo.GetExtendedStyle() | LVS_REPORT | LVS_OWNERDRAWFIXED|LVS_EX_FULLROWSELECT);
	_TCHAR *HostColumnLabel[2] ={_T("Scan Method"),_T(" Host IP Address"),};
	int HostColumnWidth[2] =	{155,180};
	LV_COLUMN lvc;
	lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
	for(int i=0;i<2;i++)
	{
		lvc.iSubItem = i;
		lvc.pszText = HostColumnLabel[i];
		lvc.cx = HostColumnWidth[i];
		lvc.fmt = LVCFMT_LEFT ;
		this->cListHostInfo.InsertColumn(i,&lvc);
	}
	this->cListPortInfo.SetExtendedStyle(this->cListPortInfo.GetExtendedStyle() | LVS_REPORT | LVS_OWNERDRAWFIXED|LVS_EX_FULLROWSELECT);
	_TCHAR *PortColumnLabel[4] ={_T("Scan Method"),_T(" Host IP Address"),_T(" Host Port"),_T("Port State"),};
	int PortColumnWidth[4] =	{100,120,87,87};
	lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
	for(i=0;i<4;i++)
	{
		lvc.iSubItem = i;
		lvc.pszText = PortColumnLabel[i];
		lvc.cx = PortColumnWidth[i];
		lvc.fmt = LVCFMT_LEFT ;
		this->cListPortInfo.InsertColumn(i,&lvc);
	}
}

void CBeastScanerDlg::InitTabCtrl(void)
{
	this->cArpScanDlg.Create(IDD_ARP_SCAN,&(this->cTabCtrl));
	this->cIcmpScanDlg.Create(IDD_ICMP_SCAN,&(this->cTabCtrl));
	this->cPortScanDlg.Create(IDD_PORT_SCAN,&(this->cTabCtrl));
	this->cTabCtrl.AddTab(&(this->cArpScanDlg),"ARP Scan",0);
	this->cTabCtrl.AddTab(&(this->cIcmpScanDlg),"ICMP Scan",1);
	this->cTabCtrl.AddTab(&(this->cPortScanDlg),"Port Scan",2);
	

	this->cTabCtrl.SelectTab(0);
}

void CBeastScanerDlg::OnOK()
{
	// TODO: 在此添加专用代码和/或调用基类
	this->cTabCtrl.SelectNextTab(TRUE);
}

void CBeastScanerDlg::OnPaint() 
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标显示。
HCURSOR CBeastScanerDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CBeastScanerDlg::OnBnClickedPause()
{
	// TODO: 在此添加控件通知处理程序代码
	if(this->enCurrentScanType!=NO_SCAN)
	{
		this->cTabCtrl.EnableWindow();
		if(bPause==false)
		{
			this->cButtonPause.SetWindowText("Resume");
			bPause=true;
			this->stCurrentState="Scan is Paused.";
			this->UpdateData(FALSE);
		}
		else
		{
			this->cButtonPause.SetWindowText("Pause");
			bPause=false;
			this->stCurrentState="Resume Scan";
			this->UpdateData(FALSE);
		}
	}
}

void CBeastScanerDlg::OnBnClickedStop()
{
	// TODO: 在此添加控件通知处理程序代码
	if(this->enCurrentScanType!=NO_SCAN)
	{
		this->enCurrentScanType=NO_SCAN;
		this->cTabCtrl.EnableWindow();
	
		this->stCurrentState="Scan is Stoped.";
		this->UpdateData(FALSE);
		bStop=true;
	}
	this->cButtonPause.SetWindowText("Pause");
	bPause=false;
}

LRESULT CBeastScanerDlg::OnBeginScan(WPARAM enCurrentScanType,LPARAM pThreadParament)
{
	if(this->enCurrentScanType==NO_SCAN)	
	{	
		if(((ThreadParament*)pThreadParament)->dwOriginalIP>((ThreadParament*)pThreadParament)->dwLastIP||((ThreadParament*)pThreadParament)->dwOriginalPort>((ThreadParament*)pThreadParament)->dwLastPort)
		{
			this->MessageBox("Set Parament Error ,Check what you set!","Error",MB_OK|MB_ICONERROR);
			return 0;
		}
		bStop=false;
		dwCurrentHostNo=0;
		dwCurrentPortInfoNo=0;
		this->enCurrentScanType=(SCAN_TYPE)enCurrentScanType;
		if(!(this->enCurrentScanType!=ARP_SCAN &&this->enCurrentScanType!=ARP_FAST_SCAN &&this->enCurrentScanType!=ICMP_WRONG_PORT_SCAN&&this->enCurrentScanType!=ICMP_IP_REORGANIZATION_SCAN&&this->enCurrentScanType!=ICMP_WRONG_PROTOCOL_SCAN&&this->enCurrentScanType!=ICMP_SCAN))
		{
			this->cListHostInfo.DeleteAllItems();
		}
		this->cListPortInfo.DeleteAllItems();
		this->cTabCtrl.EnableWindow(FALSE);
		
		this->stCurrentState="Waiting for Scan Finish…………";
		this->UpdateData(TRUE);
		((ThreadParament*)pThreadParament)->SelectDev=this->SelectDev;
		((ThreadParament*)pThreadParament)->dwHostIP=this->dwLocalIP;
		((ThreadParament*)pThreadParament)->dwDefaultGateway=this->dwDefaultGateway;
		((ThreadParament*)pThreadParament)->dwNetMAsk=this->dwNetMask;
		memcpy(((ThreadParament*)pThreadParament)->HostMac,this->bLocalMac,6);
		ScanHandler(this->enCurrentScanType,(ThreadParament*)pThreadParament);
	}
	return 0;
}
LRESULT CBeastScanerDlg::OnHandleUdpScan(WPARAM wparam,LPARAM lparam)
{
	if(this->dwCurrentPortInfoNo==0xfffffffe)
	{
		this->MessageBox("Too many PortInfo!");
		return 0;
	}
	this->cListPortInfo.InsertItem(dwCurrentPortInfoNo,"Udp Scan");
	CString Tmp;
	Tmp.Format("%u",0xffff&lparam);
	in_addr inHostIp;
	inHostIp.S_un.S_addr=htonl((DWORD)wparam);
	this->cListPortInfo.SetItemText(this->dwCurrentPortInfoNo,1,inet_ntoa(inHostIp));
	this->cListPortInfo.SetItemText(this->dwCurrentPortInfoNo,2,Tmp.GetBuffer());
	if((0xffff0000&lparam)!=0)
	{
		this->cListPortInfo.SetItemText(this->dwCurrentPortInfoNo,3,"Open/Host not exitst");
	}
	else
	{
		this->cListPortInfo.SetItemText(this->dwCurrentPortInfoNo,3,"Closed");
	}
	this->dwCurrentPortInfoNo++;
	return 0;   
}
LRESULT CBeastScanerDlg::OnHandleSynScan(WPARAM StateAndPort,LPARAM dwHostIP)
{
	if(this->dwCurrentPortInfoNo==0xfffffffe)
	{
		this->MessageBox("Too many PortInfo!");
		return 0;
	}
	this->cListPortInfo.InsertItem(dwCurrentPortInfoNo,"Tcp Syn Scan");
	in_addr inHostIp;
	inHostIp.S_un.S_addr=htonl((DWORD)dwHostIP);
	CString Tmp;
	Tmp.Format("%u",0xffff&StateAndPort);
	this->cListPortInfo.SetItemText(this->dwCurrentPortInfoNo,1,inet_ntoa(inHostIp));
	this->cListPortInfo.SetItemText(this->dwCurrentPortInfoNo,2,Tmp.GetBuffer());
	if((0xffff0000&StateAndPort)!=0)
	{
		this->cListPortInfo.SetItemText(this->dwCurrentPortInfoNo,3,"Open");
	}
	else
	{
		this->cListPortInfo.SetItemText(this->dwCurrentPortInfoNo,3,"Closed");
	}
	this->dwCurrentPortInfoNo++;
	return 0;   
}
LRESULT CBeastScanerDlg::OnHandleNullScan(WPARAM StateAndPort,LPARAM dwHostIP)
{
	if(this->dwCurrentPortInfoNo==0xfffffffe)
	{
		this->MessageBox("Too many PortInfo!");
		return 0;
	}
	this->cListPortInfo.InsertItem(dwCurrentPortInfoNo,"Tcp Null Scan");
	in_addr inHostIp;
	inHostIp.S_un.S_addr=htonl((DWORD)dwHostIP);
	CString Tmp;
	Tmp.Format("%u",0xffff&StateAndPort);
	this->cListPortInfo.SetItemText(this->dwCurrentPortInfoNo,1,inet_ntoa(inHostIp));
	this->cListPortInfo.SetItemText(this->dwCurrentPortInfoNo,2,Tmp.GetBuffer());
	this->cListPortInfo.SetItemText(this->dwCurrentPortInfoNo,3,"Closed");
	this->dwCurrentPortInfoNo++;
	return 0;      
}
LRESULT CBeastScanerDlg::OnHandleAckScan(WPARAM StateAndPort,LPARAM dwHostIP)
{
	if(this->dwCurrentPortInfoNo==0xfffffffe)
	{
		this->MessageBox("Too many PortInfo!");
		return 0;
	}
	this->cListPortInfo.InsertItem(dwCurrentPortInfoNo,"Tcp Ack Scan");
	in_addr inHostIp;
	inHostIp.S_un.S_addr=htonl((DWORD)dwHostIP);
	CString Tmp;
	Tmp.Format("%u",0xffff&StateAndPort);
	this->cListPortInfo.SetItemText(this->dwCurrentPortInfoNo,1,inet_ntoa(inHostIp));
	this->cListPortInfo.SetItemText(this->dwCurrentPortInfoNo,2,Tmp.GetBuffer());
	this->cListPortInfo.SetItemText(this->dwCurrentPortInfoNo,3,"Open");
	this->dwCurrentPortInfoNo++;
	return 0;      
}
LRESULT CBeastScanerDlg::OnHandleFinScan(WPARAM StateAndPort,LPARAM dwHostIP)
{
	if(this->dwCurrentPortInfoNo==0xfffffffe)
	{
		this->MessageBox("Too many PortInfo!");
		return 0;
	}
	this->cListPortInfo.InsertItem(dwCurrentPortInfoNo,"Tcp Fin Scan");
	in_addr inHostIp;
	inHostIp.S_un.S_addr=htonl((DWORD)dwHostIP);
	CString Tmp;
	Tmp.Format("%u",0xffff&StateAndPort);
	this->cListPortInfo.SetItemText(this->dwCurrentPortInfoNo,1,inet_ntoa(inHostIp));
	this->cListPortInfo.SetItemText(this->dwCurrentPortInfoNo,2,Tmp.GetBuffer());
	this->cListPortInfo.SetItemText(this->dwCurrentPortInfoNo,3,"Closed");
	this->dwCurrentPortInfoNo++;
	return 0;      
}
LRESULT CBeastScanerDlg::OnFinishScan(WPARAM enCurrentScanType,LPARAM pThreadParament)
{
	if(this->enCurrentScanType!=NO_SCAN)	
	{	
		if(bStop==true)
		{
			bStop=false;
			this->stCurrentState="Scan Stoped.";
		}
		else
		{
			this->stCurrentState="Scan Finished.";
		}
		
		this->cTabCtrl.EnableWindow();
		this->enCurrentScanType=NO_SCAN;
		this->UpdateData(FALSE);
	}
	this->cButtonPause.SetWindowText("Pause");
	bPause=false;
	return 0;
}
LRESULT CBeastScanerDlg::OnAddHostInfo(WPARAM ScanType/*0: ARP ;1 Icmp*/, LPARAM dwHostIP)
{
	if(dwCurrentHostNo==0xFFFFFFFe)
	{
		this->MessageBox("Too many Host!");
		return 0;
	}
	if(ScanType==0)
	{
		this->cListHostInfo.InsertItem(dwCurrentHostNo,"ARP");
	}
	else
	{
		this->cListHostInfo.InsertItem(dwCurrentHostNo,"ICMP");
	}
	in_addr inHostIp;
	inHostIp.S_un.S_addr=htonl((DWORD)dwHostIP);
	this->cListHostInfo.SetItemText(dwCurrentHostNo,1,inet_ntoa(inHostIp));
	dwCurrentHostNo++;
	return 0;
}
LRESULT CBeastScanerDlg::OnUpdataLog(WPARAM wparam,LPARAM lparam)
{
	this->stCurrentState=(char *)wparam;
	this->UpdateData(FALSE);
	return 0;
}

LRESULT CBeastScanerDlg::OnHandleConnectScan(WPARAM wparam,LPARAM lparam)
{

	if(bPause||bStop)
	{
		return 0;
	}
	WORD wEvent = WSAGETSELECTEVENT (lparam) ;   // ie, LOWORD
    WORD wError = WSAGETSELECTERROR (lparam) ;   // ie, HIWORD
	SOCKET theSocket=(SOCKET)wparam;
	if(wEvent==FD_CONNECT)
	{
		if(!wError)
		{
			if(this->dwCurrentPortInfoNo==0xfffffffe)
			{
				this->MessageBox("Too many PortInfo!");
				return 0;
			}
			SOCKADDR thePeerName;
			int size=sizeof(sockaddr);
			getpeername(theSocket,&thePeerName,&size);
			if(closesocket(theSocket)==0)
			{
					
				this->cListPortInfo.InsertItem(dwCurrentPortInfoNo,"Tcp Connect Scan");
				CString Tmp;
				Tmp.Format("%u",htons(((sockaddr_in*)(&thePeerName))->sin_port));
				this->cListPortInfo.SetItemText(this->dwCurrentPortInfoNo,1,inet_ntoa(((sockaddr_in*)(&thePeerName))->sin_addr));
				this->cListPortInfo.SetItemText(this->dwCurrentPortInfoNo,2,Tmp.GetBuffer());
				this->cListPortInfo.SetItemText(this->dwCurrentPortInfoNo,3,"Open");
				this->dwCurrentPortInfoNo++;
				return 1;
			}
		}
		
	}
	closesocket(theSocket);
	return 0;
}

void CBeastScanerDlg::OnDestroy()
{
	CDialog::OnDestroy();

	// TODO: 在此处添加消息处理程序代码
	pcap_freealldevs(alldevs);
}

CBeastScanerDlg::~CBeastScanerDlg(void)
{
	bStop=true;
	while(dwCurrentThreadNo!=0)
	{
		Sleep(100);
	}
}
