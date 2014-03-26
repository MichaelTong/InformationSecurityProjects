// TcpScanDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "BeastScaner.h"
#include "TcpScanDlg.h"
#include ".\tcpscandlg.h"


// CTcpScanDlg 对话框

IMPLEMENT_DYNAMIC(CTcpScanDlg, CDialog)
CTcpScanDlg::CTcpScanDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CTcpScanDlg::IDD, pParent)
	, shTimeoutValue(2)
	, bConnectScan(false)
	, pThreadParament(NULL)
{
	
}

CTcpScanDlg::~CTcpScanDlg()
{
}

void CTcpScanDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, CTimeOutEditCtrl);
	DDX_Text(pDX, IDC_EDIT1, shTimeoutValue);
	DDV_MinMaxShort(pDX, shTimeoutValue, 1, 10);
}


BEGIN_MESSAGE_MAP(CTcpScanDlg, CDialog)

	ON_BN_CLICKED(IDC_RADIO1, OnBnClickedRadioConnectScan)
	ON_BN_CLICKED(IDC_RADIO2, OnBnClickedRadioSYNScan)
	ON_BN_CLICKED(IDC_RADIO3, OnBnClickedRadioFINScan)
	ON_BN_CLICKED(IDC_BUTTON4, OnBnClickedStartTcpScan)
	ON_BN_CLICKED(IDC_RADIO4, OnBnClickedRadioXMan)
	ON_BN_CLICKED(IDC_RADIO5, OnBnClickedRadioNull)
END_MESSAGE_MAP()


// CTcpScanDlg 消息处理程序


void CTcpScanDlg::OnBnClickedRadioConnectScan()
{
	// TODO: 在此添加控件通知处理程序代码
	this->CTimeOutEditCtrl.EnableWindow(FALSE);
	this->emScanType=TCP_CONNECT_SCAN;

}

void CTcpScanDlg::OnBnClickedRadioSYNScan()
{
	// TODO: 在此添加控件通知处理程序代码
	this->CTimeOutEditCtrl.EnableWindow(TRUE);
	this->emScanType=TCP_SYN_SCAN;
}

void CTcpScanDlg::OnBnClickedRadioFINScan()
{
	// TODO: 在此添加控件通知处理程序代码
	
	this->CTimeOutEditCtrl.EnableWindow(TRUE);
	this->emScanType=TCP_FIN_SCAN;
}
void CTcpScanDlg::OnBnClickedRadioXMan()
{
	// TODO: 在此添加控件通知处理程序代码
	this->CTimeOutEditCtrl.EnableWindow(TRUE);
	this->emScanType=TCP_XMAN_SCAN;
}

void CTcpScanDlg::OnBnClickedRadioNull()
{
	// TODO: 在此添加控件通知处理程序代码
	this->CTimeOutEditCtrl.EnableWindow(TRUE);
	this->emScanType=TCP_NULL_SCAN;
}

BOOL CTcpScanDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// TODO:  在此添加额外的初始化
	((CButton *)GetDlgItem(IDC_RADIO1))->SetCheck(TRUE);//选上
	this->emScanType=TCP_CONNECT_SCAN;
	return TRUE;  
	// return TRUE unless you set the focus to a control
	// 异常: OCX 属性页应返回 FALSE
}

void CTcpScanDlg::OnBnClickedStartTcpScan()
{
	// TODO: 在此添加控件通知处理程序代码
	this->pParamentConstructor->SendMessage(WM_CONSTRUCT_PARAM);
	this->UpdateData();
	this->pThreadParament->dwTimeOut=this->shTimeoutValue;
	pMainWindow->SendMessage(WM_BEGIN_SCAN,this->emScanType,(LPARAM)this->pThreadParament);
}

void CTcpScanDlg::OnOK()
{
	this->OnBnClickedStartTcpScan();
}

