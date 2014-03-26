// PortScanDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "BeastScaner.h"
#include "PortScanDlg.h"
#include ".\portscandlg.h"

// CPortScanDlg 对话框

IMPLEMENT_DYNAMIC(CPortScanDlg, CDialog)
CPortScanDlg::CPortScanDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CPortScanDlg::IDD, pParent)

	, bSingleIP(FALSE)
	, bSinglePort(FALSE)
	, dwOriginateIP(0)
	, dwLastIP(0)
	, dwLastPort(1024)
	, dwOriginatePort(1)
{
}

CPortScanDlg::~CPortScanDlg()
{
}

void CPortScanDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_TAB1, cTabCtrl);
	DDX_Check(pDX, IDC_CHECK1, bSingleIP);
	DDX_Check(pDX, IDC_CHECK2, bSinglePort);
	DDX_Control(pDX, IDC_IPADDRESS2, cIPAddressCtrl);
	DDX_Control(pDX, IDC_EDIT2, cLastPortCtrl);
	DDX_IPAddress(pDX, IDC_IPADDRESS1, dwOriginateIP);
	DDX_IPAddress(pDX, IDC_IPADDRESS2, dwLastIP);
	DDX_Text(pDX, IDC_EDIT2, dwLastPort);
	DDV_MinMaxUInt(pDX, dwLastPort, 1, 65535);
	DDX_Text(pDX, IDC_EDIT1, dwOriginatePort);
	DDV_MinMaxUInt(pDX, dwOriginatePort, 1, 65535);
}


BEGIN_MESSAGE_MAP(CPortScanDlg, CDialog)

	ON_BN_CLICKED(IDC_CHECK1, OnBnClickedSingleIP)
	ON_BN_CLICKED(IDC_CHECK2, OnBnClickedSinglePort)
	ON_MESSAGE(WM_CONSTRUCT_PARAM ,OnConstructParament)
END_MESSAGE_MAP()


// CPortScanDlg 消息处理程序
BOOL CPortScanDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// TODO:  在此添加额外的初始化
	this->cTcpScanDlg.Create(IDD_TCP_SCAN,&(this->cTabCtrl));
	this->cUdpScanDlg.Create(IDD_UDP_SCAN,&(this->cTabCtrl));
	this->cTabCtrl.AddTab(&(this->cTcpScanDlg),"TCP Scan",0);
	this->cTabCtrl.AddTab(&(this->cUdpScanDlg),"UDP Scan",1);
	this->cTabCtrl.SetCurSel(0);
	this->cTcpScanDlg.pThreadParament=&(this->theThreadParament);
	this->cUdpScanDlg.pThreadParament=&(this->theThreadParament);
	this->cUdpScanDlg.pParamentConstructor=this;
	this->cTcpScanDlg.pParamentConstructor=this;
	return TRUE;  // return TRUE unless you set the focus to a control
	// 异常: OCX 属性页应返回 FALSE
}


void CPortScanDlg::OnBnClickedSingleIP()
{
	// TODO: 在此添加控件通知处理程序代码

	if(this->bSingleIP==FALSE)
	{
		this->cIPAddressCtrl.EnableWindow(FALSE);
		this->bSingleIP=TRUE;
	}
	else
	{
		this->cIPAddressCtrl.EnableWindow(TRUE);
		this->bSingleIP=FALSE;
	}
}

void CPortScanDlg::OnBnClickedSinglePort()
{
	// TODO: 在此添加控件通知处理程序代码
	if(this->bSinglePort==FALSE)
	{
		this->cLastPortCtrl.EnableWindow(FALSE);
		this->bSinglePort=TRUE;
	}
	else
	{
		this->cLastPortCtrl.EnableWindow(TRUE);
		this->bSinglePort=FALSE;
	}

}

void CPortScanDlg::OnOK()
{
	// TODO: 在此添加专用代码和/或调用基类
	this->cTabCtrl.SelectNextTab(TRUE);
}
LRESULT CPortScanDlg::OnConstructParament(WPARAM wp,LPARAM lp)
{
	this->UpdateData();
	this->theThreadParament.dwOriginalIP=this->dwOriginateIP;
	if(this->bSingleIP)
	{
		this->theThreadParament.dwLastIP=this->dwOriginateIP;
	}
	else
	{
		this->theThreadParament.dwLastIP=this->dwLastIP;
	}
	this->theThreadParament.dwOriginalPort=this->dwOriginatePort;
	if(this->bSinglePort)
	{
		this->theThreadParament.dwLastPort=this->dwOriginatePort;
	}
	else
	{
		this->theThreadParament.dwLastPort=this->dwLastPort;
	}
	return 0;
}