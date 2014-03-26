// UdpScanDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "BeastScaner.h"
#include "UdpScanDlg.h"
#include ".\udpscandlg.h"


// CUdpScanDlg 对话框

IMPLEMENT_DYNAMIC(CUdpScanDlg, CDialog)
CUdpScanDlg::CUdpScanDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CUdpScanDlg::IDD, pParent)
    ,shTimeoutValue(2)
	, pThreadParament(NULL)
	, dwTimeForOnePort(1)
	, dwTimeBetweenToPackets(0)
{
}

CUdpScanDlg::~CUdpScanDlg()
{
}

void CUdpScanDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT1, shTimeoutValue);
	DDX_Text(pDX, IDC_EDIT2, dwTimeForOnePort);
	DDX_Text(pDX, IDC_EDIT7, dwTimeBetweenToPackets);
}


BEGIN_MESSAGE_MAP(CUdpScanDlg, CDialog)
	ON_BN_CLICKED(IDC_BUTTON1, OnBnClickedUdpScan)

END_MESSAGE_MAP()


// CUdpScanDlg 消息处理程序

void CUdpScanDlg::OnBnClickedUdpScan()
{
	// TODO: 在此添加控件通知处理程序代码
	this->pParamentConstructor->SendMessage(WM_CONSTRUCT_PARAM);
	this->UpdateData();
	this->pThreadParament->dwTimeOut=this->shTimeoutValue;
	this->pThreadParament->dwTimeForOnePort=this->dwTimeForOnePort;
	this->pThreadParament->dwTimeBetweenToPackets=this->dwTimeBetweenToPackets;
	pMainWindow->SendMessage(WM_BEGIN_SCAN,UDP_SCAN,(LPARAM)this->pThreadParament);
}


void CUdpScanDlg::OnOK()
{
	this->OnBnClickedUdpScan();
}
