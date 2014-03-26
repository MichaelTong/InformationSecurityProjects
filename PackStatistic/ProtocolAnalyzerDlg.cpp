// ProtocolAnalyzerDlg.cpp : implementation file
//
#define HAVE_REMOTE
#include "stdafx.h"
#include "ProtocolAnalyzer.h"
#include "ProtocolAnalyzerDlg.h"
#include <pcap.h>
///#include "IPHelper/Iphlpapi.h"
//#include <remote-ext.h>
#include "head.h"
#include "Sort.h"
#include<comdef.h> 
#include <vector>
using namespace std;
//#pragma comment(lib,"iphlpapi")
  

#pragma comment(lib, "wpcap")
#pragma comment(lib,"ws2_32")
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

vector<CString>content;		//捕获的数据包
pcap_if_t *alldevs;
char errbuf[256+1];
pcap_t * pAdptHandle=0;
pcap_if_t * pDevGlobal=0 ;
char *filter;
/////////////////////////////////////////////////////////////////////////////
// CAboutDlg dialog used for App About

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// Dialog Data
	//{{AFX_DATA(CAboutDlg)
	enum { IDD = IDD_ABOUTBOX };
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CAboutDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	//{{AFX_MSG(CAboutDlg)
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
	//{{AFX_DATA_INIT(CAboutDlg)
	//}}AFX_DATA_INIT
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CAboutDlg)
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
	//{{AFX_MSG_MAP(CAboutDlg)
		// No message handlers
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CProtocolAnalyzerDlg dialog

CProtocolAnalyzerDlg::CProtocolAnalyzerDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CProtocolAnalyzerDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CProtocolAnalyzerDlg)
	//}}AFX_DATA_INIT
	// Note that LoadIcon does not require a subsequent DestroyIcon in Win32
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CProtocolAnalyzerDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CProtocolAnalyzerDlg)
	DDX_Control(pDX, IDC_EDIT2, m_http);
	DDX_Control(pDX, IDC_TREE1, m_tree);
	DDX_Control(pDX, IDC_EDIT1, m_data);
	DDX_Control(pDX, IDC_LIST1, m_report);
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CProtocolAnalyzerDlg, CDialog)
	//{{AFX_MSG_MAP(CProtocolAnalyzerDlg)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_COMMAND(ID_MENUITEM32772, OnStartCapture)
	ON_COMMAND(ID_MENUITEM32774, OnSetFilter)
	ON_COMMAND(ID_MENUITEM32773, OnStopCapture)
	ON_NOTIFY(NM_CLICK, IDC_LIST1, OnParticularContent)
	ON_NOTIFY(LVN_COLUMNCLICK, IDC_LIST1, OnSortPacket)
	ON_COMMAND(ID_MENUITEM32771, OnMenuitem32771)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CProtocolAnalyzerDlg message handlers


//捕获数据包线程
UINT GetPacket(LPVOID lParam)
{
	CProtocolAnalyzerDlg *p=(CProtocolAnalyzerDlg*)lParam;
	p->GetProtocolPacket();
	return 0;
}


BOOL CProtocolAnalyzerDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
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

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon
	

	// TODO: Add extra initialization here
	
	//初始化数据
	start=false;
	listNum=0;
	adapterSelected.DoModal();
	//初始化界面
	DWORD d=m_report.GetStyle();
	d=d|LVS_EX_FULLROWSELECT;
	m_report.SetExtendedStyle(d);
	TCHAR header[9][20]={_T("序号"),_T("时间"),_T("源IP"),_T("目的IP"),
		_T("协议"),_T("源地址"),_T("目的地址"),_T("帧类型"),_T("大小")};
		
	m_report.InsertColumn(0,header[0],LVCFMT_CENTER,40);
	m_report.InsertColumn(1,header[1],LVCFMT_CENTER,100);
	m_report.InsertColumn(2,header[2],LVCFMT_CENTER,110);
	m_report.InsertColumn(3,header[3],LVCFMT_CENTER,110);
	m_report.InsertColumn(4,header[4],LVCFMT_CENTER,40);
	m_report.InsertColumn(5,header[5],LVCFMT_CENTER,130);
	m_report.InsertColumn(6,header[6],LVCFMT_CENTER,130);
	m_report.InsertColumn(7,header[7],LVCFMT_CENTER,90);
	m_report.InsertColumn(8,header[8],LVCFMT_CENTER,60);

	//如果选择了网卡,则开始捕包
	if (adapterSelected.select>=0)
	{
		start=true;
		CMenu *m=this->GetMenu();   
		m->EnableMenuItem(ID_MENUITEM32772,MF_DISABLED|MF_GRAYED); 
		m->EnableMenuItem(ID_MENUITEM32773,MF_ENABLED);   
		m->EnableMenuItem(ID_MENUITEM32774,MF_DISABLED|MF_GRAYED);
		if (adapterSelected.filter=="")
		{
			//默认的过滤规则
			filter="(ether proto\\arp)or(ip)or (ip and icmp)or (ip and tcp)or (ip and udp)";
		}
		else{
			//设置过滤规则
			filter=adapterSelected.filter.GetBuffer(adapterSelected.filter.GetLength());  
		}
		AfxBeginThread(GetPacket,this);
	}
	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CProtocolAnalyzerDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CProtocolAnalyzerDlg::OnPaint() 
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, (WPARAM) dc.GetSafeHdc(), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CProtocolAnalyzerDlg::OnQueryDragIcon()
{
	return (HCURSOR) m_hIcon;
}

void CProtocolAnalyzerDlg::OnStartCapture() 
{
	// TODO: Add your command handler code here
	
	//清除界面
	select=adapterSelected.select;
	m_report.DeleteAllItems();
	m_tree.DeleteAllItems();
	m_http.SetWindowText("");
	m_data.SetWindowText("");
	listNum=0;
	content.clear();
	//如果没有选择网卡,弹出提示
	while (select<0)
	{
		adapterSelected.DoModal();
		select=adapterSelected.select;
		if (select>=0)
		{
			break;
		}
		MessageBox("请选择网卡!");
	}
	
	start=true;
	CMenu *m=this->GetMenu();
	m->EnableMenuItem(ID_MENUITEM32772,MF_DISABLED|MF_GRAYED);   
	m->EnableMenuItem(ID_MENUITEM32773,MF_ENABLED);   
	m->EnableMenuItem(ID_MENUITEM32774,MF_DISABLED|MF_GRAYED);
	

	if (adapterSelected.filter=="")
	{
		//默认的过滤规则
		filter="(ether proto\\arp)or(ip)or (ip and icmp)or (ip and tcp)or (ip and udp)";
	}
	else{
		//设置过滤规则
		filter=adapterSelected.filter.GetBuffer(adapterSelected.filter.GetLength());  
	}
	AfxBeginThread(GetPacket,this);
}

void CProtocolAnalyzerDlg::OnSetFilter() 
{
	adapterSelected.DoModal();
}

void CProtocolAnalyzerDlg::OnStopCapture() 
{
	// TODO: Add your command handler code here
	CMenu *m=this->GetMenu();   
	start=false;
	m->EnableMenuItem(ID_MENUITEM32772,MF_ENABLED);   
	m->EnableMenuItem(ID_MENUITEM32773,MF_DISABLED|MF_GRAYED);   
	m->EnableMenuItem(ID_MENUITEM32774,MF_ENABLED);   

}
///把16进制数据转化为字符串的函数///
CString HexToString(char* a,int len)
{
	CString s="";
	for (int i=0;i<len;i++)
	{
		s+=a[i];
	}
	return s;
}
//把16进制的数据转为字符串
CString IntToHexCString(unsigned int num)
{
	CString s;
	CString result="";
	char *t=(char*)&num;
	for (int i=0;i<2;i++)
	{
		int a=t[1-i];
		if (a<0)a=a+256;
		s.Format("%02x",a);
		result=result+s;
	}
	return result;
}

////捕获数据包////
void CProtocolAnalyzerDlg::GetProtocolPacket()
{
	bpf_program fcode;
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	//编译过滤规则
	if (pcap_compile(pAdptHandle, &fcode, filter, 1, (unsigned long)(0xFFFF0000)) < 0)
	{
		MessageBox("过滤规则语法错误!");
		OnStopCapture();
		return;
	}
	//过滤器
	if (pcap_setfilter(pAdptHandle, &fcode) < 0)
	{
		MessageBox("适配器与过滤条件不兼容!");
		OnStopCapture();
		return;
	}
	//开始捕包
	while(start)
	{
		res = pcap_next_ex(pAdptHandle, &header, &pkt_data);  //获得返回数据帧
		if (!res)
		{
			continue;
		}
		if (res>0)
		{
			EthernetHead *ethHead=(EthernetHead*)pkt_data;
			///如果是arp数据包////
			if (ethHead->eh_type==htons(0x0806))
			{
				//arp
				ArpPacket *arpPacket=(ArpPacket*)pkt_data;
				CString s;
				s.Format("%d",listNum+1);
				m_report.InsertItem(LVIF_TEXT|LVIF_STATE, listNum,s, 0, LVIS_SELECTED,0, 0);
				char t[32];
				//时间
				tm* time = localtime(&header->ts.tv_sec);
				strftime(t, sizeof(t), "%H:%M:%S", time);
				long lmsec =header->ts.tv_usec/1000;
				if (header->ts.tv_usec/100%10 > 5)
					lmsec += 1;
				s.Format("%s:%03d", t, lmsec);
				m_report.SetItemText(listNum,1,s);
				////////////////////////////////////
				//源ip地址
				in_addr inaddr;   
				inaddr.S_un.S_addr=(arpPacket->arp.sour_ip);   
				m_report.SetItemText(listNum,2,inet_ntoa(inaddr));
				//目的ip地址
				inaddr.S_un.S_addr=(arpPacket->arp.dest_ip); 
				m_report.SetItemText(listNum,3,inet_ntoa(inaddr));
				m_report.SetItemText(listNum,4,"ARP");
				//源mac地址
				s.Format("%02X-%02X-%02X-%02X-%02X-%02X",
					arpPacket->arp.sour_addr[0],
					arpPacket->arp.sour_addr[1],
					arpPacket->arp.sour_addr[2],
					arpPacket->arp.sour_addr[3],
					arpPacket->arp.sour_addr[4],
					arpPacket->arp.sour_addr[5]);
				m_report.SetItemText(listNum,5,s);
				//目的mac地址
				s.Format("%02X-%02X-%02X-%02X-%02X-%02X",
					arpPacket->arp.dest_addr[0],
					arpPacket->arp.dest_addr[1],
					arpPacket->arp.dest_addr[2],
					arpPacket->arp.dest_addr[3],
					arpPacket->arp.dest_addr[4],
					arpPacket->arp.dest_addr[5]);
				m_report.SetItemText(listNum,6,s);
				m_report.SetItemText(listNum,7,"ARP (0X0806)");
				//包大小
				s.Format("%d",sizeof(ArpPacket));
				m_report.SetItemText(listNum,8,s);
				listNum++;
				
				CString data=HexToString((char*)arpPacket,sizeof(ArpPacket));
				content.push_back(data);
			}
			else if (ethHead->eh_type==htons(0x0800))
			{
				IpPacket *ippacket=(IpPacket*)(pkt_data);
				///如果该ip包是伪造的,抛弃				
				int bogus=htons(ippacket->ipHead.total_len);
				if (bogus<20)
				{
					continue;
				}
				//如果ip数据包是tcp类型
				if (ippacket->ipHead.protocol==6)
				{
					//tcp
					TcpPacket *tcpPacket=(TcpPacket*)pkt_data;
				
					CString s;
					s.Format("%d",listNum+1);
					m_report.InsertItem(LVIF_TEXT|LVIF_STATE, listNum,s, 0, LVIS_SELECTED,0, 0);
					char t[32];
					//时间
					tm* time = localtime(&header->ts.tv_sec);
					strftime(t, sizeof(t), "%H:%M:%S", time);
					long lmsec =header->ts.tv_usec/1000;
					if (header->ts.tv_usec/100%10 > 5)
						lmsec += 1;
					s.Format("%s:%03d", t, lmsec);
					m_report.SetItemText(listNum,1,s);
					//源ip地址
					in_addr inaddr;   
					inaddr.S_un.S_addr=(tcpPacket->ipPacket.ipHead.sourceIP);   
					m_report.SetItemText(listNum,2,inet_ntoa(inaddr));
					//目的ip地址
					inaddr.S_un.S_addr=(tcpPacket->ipPacket.ipHead.destIP); 
					m_report.SetItemText(listNum,3,inet_ntoa(inaddr));
					m_report.SetItemText(listNum,4,"TCP");
					//源mac地址
					s.Format("%02X-%02X-%02X-%02X-%02X-%02X",
						tcpPacket->ipPacket.ethHead.source_mac[0],
						tcpPacket->ipPacket.ethHead.source_mac[1],
						tcpPacket->ipPacket.ethHead.source_mac[2],
						tcpPacket->ipPacket.ethHead.source_mac[3],
						tcpPacket->ipPacket.ethHead.source_mac[4],
						tcpPacket->ipPacket.ethHead.source_mac[5]);
					m_report.SetItemText(listNum,5,s);
					//目的mac地址
					s.Format("%02X-%02X-%02X-%02X-%02X-%02X",
						tcpPacket->ipPacket.ethHead.dest_mac[0],
						tcpPacket->ipPacket.ethHead.dest_mac[1],
						tcpPacket->ipPacket.ethHead.dest_mac[2],
						tcpPacket->ipPacket.ethHead.dest_mac[3],
						tcpPacket->ipPacket.ethHead.dest_mac[4],
						tcpPacket->ipPacket.ethHead.dest_mac[5]);
					m_report.SetItemText(listNum,6,s);
					m_report.SetItemText(listNum,7,"IP (0X0806)");
					//长度
					int len=htons(ippacket->ipHead.total_len)+14;
					s.Format("%d",len);
					m_report.SetItemText(listNum,8,s);
					listNum++;

					CString data=HexToString((char*)tcpPacket,len);
					content.push_back(data);
				}
				//如果ip数据包是udp类型
				else if(ippacket->ipHead.protocol==17){
					//udp
					UdpPacket *udpPacket=(UdpPacket*)pkt_data;
					CString s;
					s.Format("%d",listNum+1);
					m_report.InsertItem(LVIF_TEXT|LVIF_STATE, listNum,s, 0, LVIS_SELECTED,0, 0);
					char t[32];
					//时间
					tm* time = localtime(&header->ts.tv_sec);
					strftime(t, sizeof(t), "%H:%M:%S", time);
					long lmsec =header->ts.tv_usec/1000;
					if (header->ts.tv_usec/100%10 > 5)
						lmsec += 1;
					s.Format("%s:%03d", t, lmsec);
					m_report.SetItemText(listNum,1,s);
					//源IP地址
					in_addr inaddr;   
					inaddr.S_un.S_addr=(udpPacket->ipPacket.ipHead.sourceIP);   
					m_report.SetItemText(listNum,2,inet_ntoa(inaddr));
					//目的ip地址
					inaddr.S_un.S_addr=(udpPacket->ipPacket.ipHead.destIP); 
					m_report.SetItemText(listNum,3,inet_ntoa(inaddr));
					m_report.SetItemText(listNum,4,"UDP");
					//源mac地址
					s.Format("%02X-%02X-%02X-%02X-%02X-%02X",
						udpPacket->ipPacket.ethHead.source_mac[0],
						udpPacket->ipPacket.ethHead.source_mac[1],
						udpPacket->ipPacket.ethHead.source_mac[2],
						udpPacket->ipPacket.ethHead.source_mac[3],
						udpPacket->ipPacket.ethHead.source_mac[4],
						udpPacket->ipPacket.ethHead.source_mac[5]);
					m_report.SetItemText(listNum,5,s);
					//目的mac地址
					s.Format("%02X-%02X-%02X-%02X-%02X-%02X",
						udpPacket->ipPacket.ethHead.dest_mac[0],
						udpPacket->ipPacket.ethHead.dest_mac[1],
						udpPacket->ipPacket.ethHead.dest_mac[2],
						udpPacket->ipPacket.ethHead.dest_mac[3],
						udpPacket->ipPacket.ethHead.dest_mac[4],
						udpPacket->ipPacket.ethHead.dest_mac[5]);
					m_report.SetItemText(listNum,6,s);
					m_report.SetItemText(listNum,7,"IP (0X0806)");
					//长度////////////////////////////////////////
					int len=htons(ippacket->ipHead.total_len)+14;
					s.Format("%d",len);
					m_report.SetItemText(listNum,8,s);			
					listNum++;
					
					CString data=HexToString((char*)udpPacket,len);
					content.push_back(data);
				}
				//如果该ip包是icmp数据包
				else if(ippacket->ipHead.protocol==1){
					//icmp
					IcmpBasePacket *icmpBasePacket=(IcmpBasePacket*)pkt_data;
					//如果该包是数据应答 回显 超时 不可达报文中的一种
					if (icmpBasePacket->icmpBaseHead.type==8||icmpBasePacket->icmpBaseHead.type==0
						||icmpBasePacket->icmpBaseHead.type==11||icmpBasePacket->icmpBaseHead.type==3)
					{
										
						CString s;
						s.Format("%d",listNum+1);
						m_report.InsertItem(LVIF_TEXT|LVIF_STATE, listNum,s, 0, LVIS_SELECTED,0, 0);
						char t[32];
						//时间
						tm* time = localtime(&header->ts.tv_sec);
						strftime(t, sizeof(t), "%H:%M:%S", time);
						long lmsec =header->ts.tv_usec/1000;
						if (header->ts.tv_usec/100%10 > 5)
							lmsec += 1;
						s.Format("%s:%03d", t, lmsec);
						m_report.SetItemText(listNum,1,s);
						//源ip地址
						in_addr inaddr;   
						inaddr.S_un.S_addr=(ippacket->ipHead.sourceIP);   
						m_report.SetItemText(listNum,2,inet_ntoa(inaddr));
						//目的ip地址
						inaddr.S_un.S_addr=(ippacket->ipHead.destIP); 
						m_report.SetItemText(listNum,3,inet_ntoa(inaddr));
						//源mac地址
						m_report.SetItemText(listNum,4,"ICMP");
						s.Format("%02X-%02X-%02X-%02X-%02X-%02X",
							ippacket->ethHead.source_mac[0],
							ippacket->ethHead.source_mac[1],
							ippacket->ethHead.source_mac[2],
							ippacket->ethHead.source_mac[3],
							ippacket->ethHead.source_mac[4],
							ippacket->ethHead.source_mac[5]);
						m_report.SetItemText(listNum,5,s);
						//目的mac地址
						s.Format("%02X-%02X-%02X-%02X-%02X-%02X",
							ippacket->ethHead.dest_mac[0],
							ippacket->ethHead.dest_mac[1],
							ippacket->ethHead.dest_mac[2],
							ippacket->ethHead.dest_mac[3],
							ippacket->ethHead.dest_mac[4],
							ippacket->ethHead.dest_mac[5]);
						m_report.SetItemText(listNum,6,s);
						m_report.SetItemText(listNum,7,"IP (0X0806)");
						//回显或应答报文
						if (icmpBasePacket->icmpBaseHead.type==0x8||icmpBasePacket->icmpBaseHead.type==0)
						{
							IcmpEchoPacket *icmpEchoPacket =(IcmpEchoPacket*)pkt_data;	
							/////////////////报文长度
							int len=htons(ippacket->ipHead.total_len)+14;
							s.Format("%d",len);
							m_report.SetItemText(listNum,8,s);
							CString data=HexToString((char*)icmpEchoPacket,len);
							content.push_back(data);
						}
						else{
							//超时或不可达报文////////////////////////
							IcmpErrorPacket *icmpErrorPacket=(IcmpErrorPacket*)pkt_data;
							s.Format("%d",sizeof(IcmpErrorPacket));
							m_report.SetItemText(listNum,8,s);
							CString data=HexToString((char*)icmpErrorPacket,sizeof(IcmpErrorPacket));
							content.push_back(data);
						}
						listNum++;
					}
				
				}
				else{
					//其他类型的IP报文///////
					IpPacket *ipPacket=(IpPacket*)pkt_data;
					CString s;
					s.Format("%d",listNum+1);
					m_report.InsertItem(LVIF_TEXT|LVIF_STATE, listNum,s, 0, LVIS_SELECTED,0, 0);
					char t[32];
					//时间
					tm* time = localtime(&header->ts.tv_sec);
					strftime(t, sizeof(t), "%H:%M:%S", time);
					m_report.SetItemText(listNum,1,s);
					//源ip地址
					in_addr inaddr;   
					inaddr.S_un.S_addr=(ipPacket->ipHead.sourceIP);   
					m_report.SetItemText(listNum,2,inet_ntoa(inaddr));
					//目的ip地址
					inaddr.S_un.S_addr=(ipPacket->ipHead.destIP); 
					m_report.SetItemText(listNum,3,inet_ntoa(inaddr));
					m_report.SetItemText(listNum,4,"IP");
					//源mac地址
					s.Format("%02X-%02X-%02X-%02X-%02X-%02X",
						ipPacket->ethHead.source_mac[0],
						ipPacket->ethHead.source_mac[1],
						ipPacket->ethHead.source_mac[2],
						ipPacket->ethHead.source_mac[3],
						ipPacket->ethHead.source_mac[4],
						ipPacket->ethHead.source_mac[5]);
					m_report.SetItemText(listNum,5,s);
					//目的mac地址
					s.Format("%02X-%02X-%02X-%02X-%02X-%02X",
						ipPacket->ethHead.dest_mac[0],
						ipPacket->ethHead.dest_mac[1],
						ipPacket->ethHead.dest_mac[2],
						ipPacket->ethHead.dest_mac[3],
						ipPacket->ethHead.dest_mac[4],
						ipPacket->ethHead.dest_mac[5]);
					m_report.SetItemText(listNum,6,s);
					m_report.SetItemText(listNum,7,"IP (0X0806)");
					int len=htons(ippacket->ipHead.total_len)+14;
					//包长度
					s.Format("%d",len);
					m_report.SetItemText(listNum,8,s);
					listNum++;		
					CString data=HexToString((char*)ipPacket,len);
					content.push_back(data);
				}
			}
			else{
			}

		}
	}
	

}
/////显示捕获的数据包的16进制以及ascII形式
void CProtocolAnalyzerDlg::ShowDataView(char *data,int len)
{
	CString show="";
	CString s;
	CString asc="";
	s.Format("%04X",0);
	show=show+s+"    ";
	int row=len/16;
	//每行16个字符
	int countrow=0;
	if (len>row*16)
	{
		row++;
	}
	for (int i=0;i<len;i++)
	{
		int a=data[i];
		char b=data[i];
		if (b<0x20||b>0x7e)
		{
		//不可显示的asc码字符用.表示
			b='.';
		}
		asc=asc+b;
		if (a<0)a=a+256;		
		s.Format("%02X",a);
		show=show+s+" ";
		if (i%16==15)
		{
			show=show+"    "+asc+"\r\n";
			asc="";		
			s.Format("%04X",i+1);
			if(i!=len-1)
				show=show+s+"    ";
				countrow++;
		}
	}
	int rest=len-countrow*16;
	for (i=0;i<16-rest;i++)
	{
		show=show+" "+"  ";
	}
	show=show+"    "+asc;
	m_data.SetWindowText(show);
}





//网际校验和算法
USHORT CheckSum(const char *buf, int size) 
{ 
	USHORT *buffer=(USHORT *)buf;
	unsigned long cksum=0; 
	while(size >1) 
	{ 
		cksum+=*buffer++; 
		size -=sizeof(USHORT); 
	} 
	if(size ) 
	{ 
		cksum += *(UCHAR*)buffer; 
	} 
	
	cksum = (cksum >> 16) + (cksum & 0xffff); 
	cksum += (cksum >>16); 
	return (USHORT)(~cksum); 
} 

//tcp校验和算法
unsigned short TcpCheckSum(const char *pTcpData, const char *pPshData, UINT nTcpCount)
{
	unsigned short sCheckSum = ~CheckSum(pTcpData,nTcpCount);
	unsigned long checkSum = sCheckSum;
	checkSum <<= 16;
	sCheckSum = ~CheckSum(pPshData,12);
	checkSum += sCheckSum;		
	return CheckSum((char*)&checkSum,4);
}
//udp校验和算法
unsigned short UdpCheckSum(const char *pTcpData, const char *pPshData, UINT nTcpCount)
{
	unsigned short sCheckSum = ~CheckSum(pTcpData,nTcpCount);
	unsigned long checkSum = sCheckSum;
	checkSum <<= 16;
	sCheckSum = ~CheckSum(pPshData,12);
	checkSum += sCheckSum;	
	return CheckSum((char*)&checkSum,4);
}



////显示应用层数据
void CProtocolAnalyzerDlg::ShowApplicationsView(char *data, int len)
{
	m_http.SetWindowText("");	
	EthernetHead *ethHead=(EthernetHead*)data;
	CString temp;
	CString show="";
	if (ethHead->eh_type==htons(0x0800)){
		//如果是IP包
		IpPacket *ippacket=(IpPacket*)(data);
		if (ippacket->ipHead.protocol==6){
			//如果是TCP包
			TcpPacket *tcpPacket=(TcpPacket*)data;
			temp=(ippacket->ipHead.hdr_len+48);
			int ipHeader=atoi(temp)*4;
			temp.Format("%d",htons(ippacket->ipHead.total_len));
			int totalLength=atoi(temp);
			temp.Format("%d",(tcpPacket->tcpHead.length>>4));
			int tcpHeader=atoi(temp)*4;
			//tcp含有的数据长度	
			int dataLength=totalLength-tcpHeader-ipHeader;
			char *t=(char*)(data+tcpHeader+ipHeader+14);		
			if ((htons(tcpPacket->tcpHead.destPort)==80||htons(tcpPacket->tcpHead.sourcePort)==80)
				&&dataLength)
			{
				///http数据报
				temp.Format("%s",t);
				//不显示数据部分
				//只是显示报头
				if(temp.Find("HTTP/")!=-1){	
					int flag=dataLength;
					for (int i=0;i<dataLength-3;i++)
					{
						//是以\r\n分隔的
						if (t[i]=='\r'&&t[i+1]=='\n'&&t[i+2]=='\r'&&t[i+3]=='\n')
						{
							flag=i;
							break;
						}
					}	
					temp.Format("%s",t);	
					show=temp.Mid(0,flag+3);
				}
			}
			//ftp数据报
			if ((htons(tcpPacket->tcpHead.destPort)==21||htons(tcpPacket->tcpHead.sourcePort)==21)
				&&dataLength){
				show.Format("%s",t);
			}
			//smtp数据报
			if ((htons(tcpPacket->tcpHead.destPort)==25||htons(tcpPacket->tcpHead.sourcePort)==25)
				&&dataLength){
				show.Format("%s",t);
			}

		}
	}
	m_http.SetWindowText(show);
}

///显示数据包详细信息
void CProtocolAnalyzerDlg::ShowContentView(char* data,int len,int row)
{
	m_tree.DeleteAllItems();
	
	EthernetHead *ethHead=(EthernetHead*)data;
	CString temp;
	//Frame信息
	HTREEITEM hframe =m_tree.InsertItem(_T("Frame"),TVI_ROOT,TVI_LAST);
	temp=m_report.GetItemText(row,1);
	m_tree.InsertItem(_T("Arrival Time:")+temp,hframe);
	temp=m_report.GetItemText(row,0);
	m_tree.InsertItem(_T("Frame Number:")+temp,hframe);
	temp.Format("%d",len);
	temp=temp+"bytes";
	m_tree.InsertItem(_T("Packet Length:")+temp,hframe);
	m_tree.Expand(hframe,TVE_EXPAND);
	HTREEITEM eth =m_tree.InsertItem(_T("Ethernet II"),TVI_ROOT,TVI_LAST);
	//以太网信息//
	EthernetHead *ethernet=(EthernetHead*)data;
	//源mac地址
	temp.Format("%02X-%02X-%02X-%02X-%02X-%02X",
		ethernet->source_mac[0],
		ethernet->source_mac[1],
		ethernet->source_mac[2],
		ethernet->source_mac[3],
		ethernet->source_mac[4],
		ethernet->source_mac[5]);
	m_tree.InsertItem(_T("Source Mac:")+temp,eth);
	//目的mac地址
	temp.Format("%02X-%02X-%02X-%02X-%02X-%02X",
		ethernet->dest_mac[0],
		ethernet->dest_mac[1],
		ethernet->dest_mac[2],
		ethernet->dest_mac[3],
		ethernet->dest_mac[4],
		ethernet->dest_mac[5]);	
	m_tree.InsertItem(_T("Destination Mac:")+temp,eth);

	if (ethHead->eh_type==htons(0x0806)){
		//arp信息
		m_tree.InsertItem(_T("Type: ARP(0x0806)"),eth);
		m_tree.Expand(eth,TVE_EXPAND);
		//////////////////arp view/////////////////////////////
		
		HTREEITEM arp =m_tree.InsertItem(_T("Address Resolution Protocol"),TVI_ROOT,TVI_LAST);
		ArpPacket *arpPacket=(ArpPacket*)data;
		//类型
		m_tree.InsertItem(_T("Hardware type:Ethernet(0x0001)"),arp);
		//协议类型
		m_tree.InsertItem(_T("Protocol type:IP(0x0800)"),arp);
		//硬件地址长度
		m_tree.InsertItem(_T("Hardware size:6"),arp);
		//协议地址长度
		m_tree.InsertItem(_T("Protocol:4"),arp);
		//报文类型
		unsigned short type=htons(arpPacket->arp.option);
		if (type==0x0001)
		{
			m_tree.InsertItem(_T("Opcode: request(0x0001)"),arp);
		}
		else
		{
			m_tree.InsertItem(_T("Opcode: reply(0x0002)"),arp);
		}
		//源mac地址
		temp.Format("%02X-%02X-%02X-%02X-%02X-%02X",
			arpPacket->arp.sour_addr[0],
			arpPacket->arp.sour_addr[1],
			arpPacket->arp.sour_addr[2],
			arpPacket->arp.sour_addr[3],
			arpPacket->arp.sour_addr[4],
			arpPacket->arp.sour_addr[5]);
		m_tree.InsertItem(_T("Sender Mac adress")+temp,arp);
		//源ip地址
		unsigned long source=arpPacket->arp.sour_ip;
		in_addr inaddr;   
		inaddr.S_un.S_addr=(source); 
		temp=inet_ntoa(inaddr);
		m_tree.InsertItem(_T("Sender IP adress")+temp,arp);
		//目的mac地址
		temp.Format("%02X-%02X-%02X-%02X-%02X-%02X",
			arpPacket->arp.dest_addr[0],
			arpPacket->arp.dest_addr[1],
			arpPacket->arp.dest_addr[2],
			arpPacket->arp.dest_addr[3],
			arpPacket->arp.dest_addr[4],
			arpPacket->arp.dest_addr[5]);
		m_tree.InsertItem(_T("Target Mac adress")+temp,arp);
		//目的IP地址
		unsigned long dest=arpPacket->arp.dest_ip;
		inaddr.S_un.S_addr=(dest); 
		temp=inet_ntoa(inaddr);
		m_tree.InsertItem(_T("Target IP adress")+temp,arp);
		m_tree.Expand(arp,TVE_EXPAND);

	}
	else if (ethHead->eh_type==htons(0x0800))
	{
		//IP层///////////////////////////////////////
		m_tree.InsertItem(_T("Type: IP(0x0800)"),eth);
		m_tree.Expand(eth,TVE_EXPAND);
		IpPacket *ippacket=(IpPacket*)(data);
		HTREEITEM ip =m_tree.InsertItem(_T("Internet Protocol"),TVI_ROOT,TVI_LAST);
		temp=(ippacket->ipHead.version+48);
		//版本号
		m_tree.InsertItem(_T("Version:")+temp,ip);
		///ip头长度
		temp=(ippacket->ipHead.hdr_len+48);
		int ipLength=atoi(temp)*4;
		temp.Format("%d",ipLength);
		temp=temp+"bytes";
		m_tree.InsertItem(_T("Header length:")+temp,ip);
		////TOS
		int a=ippacket->ipHead.tos;
		if (a<0)a=a+256;		
		temp.Format("%02x",a);
		//服务类型
		m_tree.InsertItem(_T("Type of service:Ox")+temp,ip);
		//总长度
		temp.Format("%d",htons(ippacket->ipHead.total_len));
		m_tree.InsertItem(_T("Total Length:")+temp,ip);
		//标示字段
		unsigned short id=htons(ippacket->ipHead.identifier);		
		CString s;
		s.Format("%d",id);
		temp=IntToHexCString(id);
		temp=temp+"("+s+")";
		m_tree.InsertItem(_T("Identification:0x")+temp,ip);
		//标志字段
		unsigned short frag=htons(ippacket->ipHead.frag_and_flags);
		char flags=(frag>>12);
		temp.Format("%02x",flags);
		m_tree.InsertItem(_T("Flags:0x")+temp,ip);
		//偏移字段
		unsigned short offset=(frag)&(0x1FFF);
		temp.Format("%d",offset);
		m_tree.InsertItem(_T("Fragment offset:")+temp,ip);
		///TTL
		unsigned char ttl=ippacket->ipHead.ttl;
			temp.Format("%d",ttl);
		m_tree.InsertItem(_T("Time to live:")+temp,ip);
		//校验和
		unsigned short real=CheckSum((const char *)&(ippacket->ipHead),sizeof(IpHead));
		unsigned short crc=(ippacket->ipHead.check_sum);
		temp=IntToHexCString(htons(crc));

		if (real==0)
		{
			//正确
			temp=temp+"[correct]";
		}
		else{
			//如果错误,需要重新校验
			ippacket->ipHead.check_sum=0;
			real=CheckSum((const char *)&((ippacket->ipHead)),sizeof(IpHead));
			temp=temp+"[incorrect,should be 0x"+IntToHexCString(htons(real))+"]";
			ippacket->ipHead.check_sum=(crc);
		}
		m_tree.InsertItem(_T("Header checksum: 0x")+temp,ip);
		///源ip地址
		unsigned long source=ippacket->ipHead.sourceIP;
		in_addr inaddr;   
		inaddr.S_un.S_addr=(source); 
		temp=inet_ntoa(inaddr);
		m_tree.InsertItem(_T("Source:")+temp,ip);
		//目的ip地址
		unsigned long dest=ippacket->ipHead.destIP;
		inaddr.S_un.S_addr=(dest);  
		temp=inet_ntoa(inaddr);
		m_tree.InsertItem(_T("Destination:")+temp,ip);
			
		///////tcp报文解析/////////////////
		if (ippacket->ipHead.protocol==6)
		{
			m_tree.InsertItem(_T("Protocol: TCP(0x06)"),ip);
			m_tree.Expand(ip,TVE_EXPAND);
			HTREEITEM tcp =m_tree.InsertItem(_T("Transmission Control Protocol"),TVI_ROOT,TVI_LAST);
			//m_tree.Expand(tcp,TVE_EXPAND);
			TcpPacket *tcpPacket=(TcpPacket*)data;
			
			//源端口号
			unsigned short port=htons(tcpPacket->tcpHead.sourcePort);
			temp.Format("%u",port);
			m_tree.InsertItem(_T("Source port:")+temp,tcp);
			//目的端口号
		    port=htons(tcpPacket->tcpHead.destPort);
			temp.Format("%u",port);
			m_tree.InsertItem(_T("Destination port:")+temp,tcp);
			//seq num
			unsigned long seq=(tcpPacket->tcpHead.seq);
			temp.Format("%lu",seq);
			m_tree.InsertItem(_T("Sequence number:")+temp,tcp);
			//ack
			unsigned long ack=(tcpPacket->tcpHead.ack);
			temp.Format("%lu",ack);
			m_tree.InsertItem(_T("Acknowledge number:")+temp,tcp);
			///tcp头长度
			temp.Format("%d",(tcpPacket->tcpHead.length>>4));
			int tcpLength=atoi(temp)*4;
			temp.Format("%d",tcpLength);
			m_tree.InsertItem(_T("Header length:")+temp,tcp);
			m_tree.InsertItem(_T("Reserved:0x0"),tcp);

			unsigned char tcpflags=tcpPacket->tcpHead.flag;
			temp.Format("%02x",tcpflags);	
			//tcp标志字段
			HTREEITEM flagTcp =m_tree.InsertItem(_T("Flags:0x")+temp,tcp,TVI_LAST);
			temp.Format("%x",(tcpflags>>5)&0x1);
			//urg位
			m_tree.InsertItem(_T("URG:")+temp,flagTcp);
			temp.Format("%x",(tcpflags>>4)&0x1);
			//ack位
			m_tree.InsertItem(_T("ACK:")+temp,flagTcp);
			temp.Format("%x",(tcpflags>>3)&0x1);
			//psh位
			m_tree.InsertItem(_T("PSH:")+temp,flagTcp);
			temp.Format("%x",(tcpflags>>2)&0x1);
			//rst位
			m_tree.InsertItem(_T("RST:")+temp,flagTcp);
			temp.Format("%x",(tcpflags>>1)&0x1);
			//syn位
			m_tree.InsertItem(_T("SYN:")+temp,flagTcp);
			temp.Format("%x",(tcpflags>>0)&0x1);
			//fin位
			m_tree.InsertItem(_T("FIN:")+temp,flagTcp);
			m_tree.Expand(flagTcp,TVE_EXPAND);
			//窗口大小
			unsigned short size=htons(tcpPacket->tcpHead.window);
			temp.Format("%u",size);
			m_tree.InsertItem(_T("Windows size:")+temp,tcp);
			//构造tcp伪头部
			TcpFakeHeader tcpFaker;
			tcpFaker.bZero=0;
			tcpFaker.destIP=(tcpPacket->ipPacket.ipHead.destIP);
			tcpFaker.protocol=6;
			tcpFaker.sourceIP=(tcpPacket->ipPacket.ipHead.sourceIP);
			tcpFaker.tcpLength=htons(htons(ippacket->ipHead.total_len)-ipLength);	
			unsigned short tcpcrc=(tcpPacket->tcpHead.crc);
			unsigned short real=TcpCheckSum((char *)&(tcpPacket->tcpHead),(char *)&(tcpFaker),htons(ippacket->ipHead.total_len)-ipLength);
			//tcp校验和
			temp=IntToHexCString(htons(tcpcrc));
			if (real==0)
			{
				temp=temp+"[correct]";
			}
			else{
				//如果tcp校验和错误,则纠正
				tcpPacket->tcpHead.crc=0;
				real=TcpCheckSum((char *)&(tcpPacket->tcpHead),(char *)&(tcpFaker),htons(ippacket->ipHead.total_len)-ipLength);
				temp=temp+"[incorrect,should be 0x"+IntToHexCString(htons(real))+"]";
				tcpPacket->tcpHead.crc=tcpcrc;
			}
			m_tree.InsertItem(_T("Checksum:0x")+temp,tcp);
			//指针	
			unsigned short urgent=(tcpPacket->tcpHead.urgent);
			temp.Format("%u",urgent);
			m_tree.InsertItem(_T("Urgent pointer:")+temp,tcp);
			//选项字段
			int options=tcpLength-20;
			if (!options)
			{
				temp="None";
			}
			else{
				temp.Format("%dbytes",options);
			}
			m_tree.InsertItem(_T("Options:")+temp,tcp);
			m_tree.Expand(tcp,TVE_EXPAND);
		}
		else if (ippacket->ipHead.protocol==17)
		{
			m_tree.InsertItem(_T("Protocol: UDP(0x11)"),ip);
			m_tree.Expand(ip,TVE_EXPAND);
			/////////////////////////udp view////////////////////
			UdpPacket *udppacket=(UdpPacket*)data;
			HTREEITEM udp =m_tree.InsertItem(_T("User Datagram Protocol"),TVI_ROOT,TVI_LAST);
			//源端口号
			unsigned short port=htons(udppacket->udpHead.sourcePort);
			temp.Format("%u",port);
			m_tree.InsertItem(_T("Source port:")+temp,udp);
			//目的端口号
		    port=htons(udppacket->udpHead.destPort);
			temp.Format("%u",port);
			m_tree.InsertItem(_T("Destination port:")+temp,udp);
			//udp长度
			unsigned short udpLength=htons(udppacket->udpHead.length);
			temp.Format("%u",udpLength);
			m_tree.InsertItem(_T("Length:")+temp,udp);
			///构造udp伪头部
			UdpFakeHeader udpFaker;
			udpFaker.bZero=0;
			udpFaker.destIP=(udppacket->ipPacket.ipHead.destIP);
			udpFaker.protocol=17;
			udpFaker.sourceIP=(udppacket->ipPacket.ipHead.sourceIP);
			udpFaker.udpLength=htons(htons(ippacket->ipHead.total_len)-ipLength);
			
			///校验和
			unsigned short crc=(udppacket->udpHead.crc);
			unsigned short real=UdpCheckSum((char *)&(udppacket->udpHead),(char *)&(udpFaker),htons(ippacket->ipHead.total_len)-ipLength);
			temp=IntToHexCString(htons(crc));
			if (real==0)
			{
				temp=temp+"[correct]";
			}
			else{
				//如果校验和错误,则纠正之
				udppacket->udpHead.crc=0;
				real=UdpCheckSum((char *)&(udppacket->udpHead),(char *)&(udpFaker),htons(ippacket->ipHead.total_len)-ipLength);
				temp=temp+"[incorrect,should be 0x"+IntToHexCString(htons(real))+"]";
				udppacket->udpHead.crc=crc;
			}
			m_tree.InsertItem(_T("Checksum:0x")+temp,udp);
			m_tree.Expand(udp,TVE_EXPAND);	
		}
		else if (ippacket->ipHead.protocol==1)
		{
			//ICMP包/////////////////////////////////////////////
			/////////////////////////icmp view////////////////////
			m_tree.InsertItem(_T("Protocol: ICMP(0x01)"),ip);
			m_tree.Expand(ip,TVE_EXPAND);
			IcmpBasePacket *icmpBasePacket=(IcmpBasePacket*)data;
			HTREEITEM icmp =m_tree.InsertItem(_T("Internet Control Message Protocol"),TVI_ROOT,TVI_LAST);
			//icmp包类型
			temp=icmpBasePacket->icmpBaseHead.type+48;
			if(icmpBasePacket->icmpBaseHead.type==11){
				temp="11 (Time Exceeded) ";
			}
			if(icmpBasePacket->icmpBaseHead.type==8){
				temp="8 (Echo Request) ";
			}
			if(icmpBasePacket->icmpBaseHead.type==0){
				temp="0 (Echo Reply) ";
			}
			if(icmpBasePacket->icmpBaseHead.type==3){
				temp="3 (UnReachable) ";
			}
			m_tree.InsertItem(_T("Type:")+temp,icmp);
			////code
			temp=icmpBasePacket->icmpBaseHead.code+48;
			m_tree.InsertItem(_T("Code:")+temp,icmp);
			//应答或回显报文
			if (icmpBasePacket->icmpBaseHead.type==0||icmpBasePacket->icmpBaseHead.type==8)
			{
				IcmpEchoPacket *icmpEchoPacket=(IcmpEchoPacket*)data;
				unsigned short crc=(icmpEchoPacket->icmpEchoHeader.icmpbasehead.cksum);
				temp=IntToHexCString(htons(crc));
				real=CheckSum((const char *)&((icmpEchoPacket->icmpEchoHeader)),8+32);
				////校验和及其纠正///////////////////////////////////////////////////////////	
				if (real==0)
				{
					temp=temp+"[correct]";
				}
				else{
					icmpEchoPacket->icmpEchoHeader.icmpbasehead.cksum=0;
					real=CheckSum((const char *)&((icmpEchoPacket->icmpEchoHeader)),8+32);
					temp=temp+"[incorrect,should be 0x"+IntToHexCString(htons(real))+"]";
					icmpEchoPacket->icmpEchoHeader.icmpbasehead.cksum=(crc);
				}
				m_tree.InsertItem(_T("Checksum:0x")+temp,icmp);

				/////id
				unsigned short id=htons(icmpEchoPacket->icmpEchoHeader.id);
				temp=IntToHexCString((id));		
				m_tree.InsertItem(_T("Identifier:0x")+temp,icmp);	
				////Sequence number///////////////////////////
				unsigned short seq=htons(icmpEchoPacket->icmpEchoHeader.seq);
				temp=IntToHexCString((seq));	
				m_tree.InsertItem(_T("Sequence number:0x")+temp,icmp);
				/////////////////////////////////////////////////
				int bytes=htons(ippacket->ipHead.total_len)-20-8;
				temp.Format("%d",bytes);
				temp=temp+"bytes";
				m_tree.InsertItem(_T("Data:")+temp,icmp);
				m_tree.Expand(icmp,TVE_EXPAND);
			}
			else{
				///icmp错误报文////////////////////////////////////////////////////////
				IcmpErrorPacket *icmpErrorPacket=(IcmpErrorPacket*)data;
				unsigned short crc=(icmpErrorPacket->icmpErrorHeader.icmpbasehead.cksum);
				temp=IntToHexCString(htons(crc));
				real=CheckSum((const char *)&((icmpErrorPacket->icmpErrorHeader)),sizeof(IcmpEchoHeader));
				/////校验和///////////////////////////////////////////////////////////	
				if (real==0)
				{
					temp=temp+"[correct]";
				}
				else{
					icmpErrorPacket->icmpErrorHeader.icmpbasehead.cksum=0;
					real=CheckSum((const char *)&((icmpErrorPacket->icmpErrorHeader)),sizeof(IcmpEchoHeader));
					temp=temp+"[incorrect,should be 0x"+IntToHexCString(htons(real))+"]";
					icmpErrorPacket->icmpErrorHeader.icmpbasehead.cksum=(crc);
				}
				m_tree.InsertItem(_T("Checksum:0x")+temp,icmp);
				///////////////////////////////////////////////////////////////////////////
				m_tree.InsertItem(_T("Unused:0"),icmp);
				m_tree.Expand(icmp,TVE_EXPAND);
				/////////////////////////////////////////////ip////////////////////////
				HTREEITEM ip2=m_tree.InsertItem(_T("Internet Protocol"),icmp,TVI_LAST);	
				////产生差错的数据报IP头部//////////////////////////////////////////////////////////////
				IpHead ipHead=icmpErrorPacket->ipHead;
				temp=(ipHead.version+48);
				//版本号
				m_tree.InsertItem(_T("Version:")+temp,ip2);
				temp=(ipHead.hdr_len+48);
				//头部长度
				int ipLength=atoi(temp)*4;
				temp.Format("%d",ipLength);
				temp=temp+"bytes";
				m_tree.InsertItem(_T("Header length:")+temp,ip2);	
				//tos
				int a=ipHead.tos;
				if (a<0)a=a+256;		
				temp.Format("%02x",a);
				///总长度
				m_tree.InsertItem(_T("Type of service:Ox")+temp,ip2);	
				temp.Format("%d",htons(ipHead.total_len));
				m_tree.InsertItem(_T("Total Length:")+temp,ip2);
				//id
				unsigned short id=htons(ipHead.identifier);		
				CString s;
				s.Format("%d",id);
				temp=IntToHexCString(id);
				temp=temp+"("+s+")";
				m_tree.InsertItem(_T("Identification:0x")+temp,ip2);
				unsigned short frag=htons(ipHead.frag_and_flags);
				//标志字段
				char flags=(frag>>12);
				temp.Format("%02x",flags);
				m_tree.InsertItem(_T("Flags:0x")+temp,ip2);
				unsigned short offset=(frag)&(0x1FFF);
				temp.Format("%d",offset);
				m_tree.InsertItem(_T("Fragment offset:")+temp,ip2);		
				unsigned char ttl=ipHead.ttl;
				temp.Format("%d",ttl);
				//ttl///////////////////////////////////////////////
				m_tree.InsertItem(_T("Time to live:")+temp,ip2);
				
				//校验和
				unsigned short real=CheckSum((const char *)&(ipHead),sizeof(IpHead));
				crc=(ipHead.check_sum);
				temp=IntToHexCString(htons(crc));		
				if (real==0)
				{
					temp=temp+"[correct]";
				}
				else{
					ipHead.check_sum=0;
					real=CheckSum((const char *)&((ipHead)),sizeof(IpHead));
					temp=temp+"[incorrect,should be 0x"+IntToHexCString(htons(real))+"]";
					ipHead.check_sum=(crc);
				}
				m_tree.InsertItem(_T("Header checksum: 0x")+temp,ip2);
				//源ip地址
				unsigned long source=ipHead.sourceIP;
				in_addr inaddr;   
				inaddr.S_un.S_addr=(source); 
				temp=inet_ntoa(inaddr);
				m_tree.InsertItem(_T("Source:")+temp,ip2);
				//目的ip地址
				unsigned long dest=ipHead.destIP;
				inaddr.S_un.S_addr=(dest);  
				temp=inet_ntoa(inaddr);
				m_tree.InsertItem(_T("Destination:")+temp,ip2);
				m_tree.Expand(ip2,TVE_EXPAND);
				//////////////////icmp2////////////////////////////	
				/////超时差错报文
				if(icmpBasePacket->icmpBaseHead.type==11){
					IcmpEchoHeader icmpEchoHeader=icmpErrorPacket->icmpEchoHeader;
					HTREEITEM icmp2=m_tree.InsertItem(_T("Internet Control Message Protocol"),icmp,TVI_LAST);
					temp="11 (Time Exceeded) ";
					//类型
					m_tree.InsertItem(_T("Type:")+temp,icmp2);
					//code
					temp=icmpEchoHeader.icmpbasehead.code+48;
					m_tree.InsertItem(_T("Code:")+temp,icmp2);
					//校验和
					crc=(icmpEchoHeader.icmpbasehead.cksum);
					temp=IntToHexCString(htons(crc));
					temp=temp+"[correct]";
					m_tree.InsertItem(_T("Checksum:0x")+temp,icmp2);
					//////////////////////////////////////////////////////////////////
					unsigned short id=htons(icmpEchoHeader.id);
					temp=IntToHexCString((id));
					////id
					m_tree.InsertItem(_T("Identifier:0x")+temp,icmp2);		
					////seq/////////////////////////
					unsigned short seq=htons(icmpEchoHeader.seq);
					temp=IntToHexCString((seq));	
					m_tree.InsertItem(_T("Sequence number:0x")+temp,icmp2);
					m_tree.Expand(icmp2,TVE_EXPAND);
				}
				if(icmpBasePacket->icmpBaseHead.type==3){
					//不可达报文
					IcmpUnReachablePacket *unreachable=(IcmpUnReachablePacket*)data;
					HTREEITEM icmp2=m_tree.InsertItem(_T("User Datagram Protocol"),icmp,TVI_LAST);
					UdpHead udpHead=unreachable->udpHead;
					////udp//////////////////////////////////////////////////////////////////////////
					//端口号
					unsigned short port=htons(udpHead.sourcePort);
					temp.Format("%u",port);
					m_tree.InsertItem(_T("Source port:")+temp,icmp2);	
					port=htons(udpHead.destPort);
					temp.Format("%u",port);
					m_tree.InsertItem(_T("Destination port:")+temp,icmp2);
					//udp长度
					unsigned short udpLength=htons(udpHead.length);
					temp.Format("%u",udpLength);
					m_tree.InsertItem(_T("Length:")+temp,icmp2);
					//crc校验
					unsigned short crc=(udpHead.crc);
					temp=IntToHexCString(htons(crc));
					m_tree.InsertItem(_T("Checksum:0x")+temp,icmp2);
					m_tree.Expand(icmp2,TVE_EXPAND);
				}
			}
		
		}
		else{
			//其他类型的IP报文
			unsigned char protocol=ippacket->ipHead.protocol;
			temp.Format("%02x",protocol);
			temp=" (0x"+temp+")";
			m_tree.InsertItem(_T("Protocol: Others")+temp,ip);
		}
	}

}
////对指定包进行分析//////////////////////////////////
void CProtocolAnalyzerDlg::OnParticularContent(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here
	int i=m_report.GetSelectionMark();
	if (i>=0)
	{
		CString num=m_report.GetItemText(i,0);
		int currentNum=atoi(num)-1;
		CString data=content[currentNum];
		char *pktData=data.GetBuffer(data.GetLength());
		ShowDataView(pktData,data.GetLength());
		ShowApplicationsView(pktData,data.GetLength());
		ShowContentView(pktData,data.GetLength(),i);
	}
	
	*pResult = 0;
}
//////////////////对列表进行排序/////////////////////////////
void CProtocolAnalyzerDlg::OnSortPacket(NMHDR* pNMHDR, LRESULT* pResult) 
{
	NM_LISTVIEW* pNMListView = (NM_LISTVIEW*)pNMHDR;
	// TODO: Add your control notification handler code here
	int nID=pNMListView->iSubItem; 
	for(int i = 0; i < m_report.GetItemCount(); i++){
		m_report.SetItemData(i,i);	
	}
	////回调函数///////
	if(nID==0){
		m_report.SortItems(MyCompareProc0,(DWORD)&m_report); 
	}
	if(nID==1){
		m_report.SortItems(MyCompareProc1,(DWORD)&m_report); 
	}	
	if(nID==2){
		m_report.SortItems(MyCompareProc2,(DWORD)&m_report); 
	}	
	if(nID==3){
		m_report.SortItems(MyCompareProc3,(DWORD)&m_report); 
	}	
	if(nID==4){
		m_report.SortItems(MyCompareProc4,(DWORD)&m_report); 
	}	
	if(nID==5){
		m_report.SortItems(MyCompareProc5,(DWORD)&m_report); 
	}	
	if(nID==6){
		m_report.SortItems(MyCompareProc6,(DWORD)&m_report); 
	}
	if(nID==7){
		m_report.SortItems(MyCompareProc7,(DWORD)&m_report); 
	}
	if(nID==8){
		m_report.SortItems(MyCompareProc8,(DWORD)&m_report); 
	}
	*pResult = 0;
}
////退出///////////////////////////////
void CProtocolAnalyzerDlg::OnMenuitem32771() 
{
	// TODO: Add your command handler code here
	
	CDialog::DestroyWindow();
}

