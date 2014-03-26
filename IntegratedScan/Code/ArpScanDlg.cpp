// ArpScanDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "BeastScaner.h"
#include "ArpScanDlg.h"
#include ".\arpscandlg.h"


// CArpScanDlg �Ի���

IMPLEMENT_DYNAMIC(CArpScanDlg, CDialog)
CArpScanDlg::CArpScanDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CArpScanDlg::IDD, pParent)
	, strHostMAc(_T(""))
	//, strHostIPAddress(_T(""))
	, strHostName(_T(""))
	, dwTimeOutValue(2)
	, dwLocalIP(0)
	, dwNetMask(0)
	, dwDefaultGateway(0)
	, strLocalIp(_T(""))
	, strNetMask(_T(""))
	, strDefaultGateway(_T(""))
{
}

CArpScanDlg::~CArpScanDlg()
{
}

void CArpScanDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT1, strHostMAc);
	//	DDX_Text(pDX, IDC_EDIT2, strHostIPAddress);
	DDX_Text(pDX, IDC_EDIT3, strHostName);
	DDX_Text(pDX, IDC_EDIT4, dwTimeOutValue);
	DDV_MinMaxUInt(pDX, dwTimeOutValue, 1, 5);

	DDX_Text(pDX, IDC_EDIT2, strLocalIp);
	DDX_Text(pDX, IDC_EDIT5, strNetMask);
	DDX_Text(pDX, IDC_EDIT6, strDefaultGateway);
}


BEGIN_MESSAGE_MAP(CArpScanDlg, CDialog)
	ON_BN_CLICKED(IDC_BUTTON1, OnBnClickedSlowScan)
	ON_BN_CLICKED(IDC_BUTTON2, OnBnClickedFastScan)
END_MESSAGE_MAP()


// CArpScanDlg ��Ϣ�������

void CArpScanDlg::OnBnClickedSlowScan()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	this->theThreadParament.dwOriginalIP=(this->dwLocalIP&0xFFFFFF00)+1;
	this->theThreadParament.dwLastIP=(this->dwLocalIP&0xFFFFFF00)+254;
	
	pMainWindow->SendMessage(WM_BEGIN_SCAN,ARP_SCAN,(LPARAM)&(this->theThreadParament));
}

void CArpScanDlg::OnBnClickedFastScan()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	this->UpdateData();
	this->theThreadParament.dwOriginalIP=(this->dwLocalIP&0xFFFFFF00)+1;
	this->theThreadParament.dwLastIP=(this->dwLocalIP&0xFFFFFF00)+254;
	this->theThreadParament.dwHostIP=this->dwLocalIP;
	memcpy(this->theThreadParament.HostMac,this->bLocalMac,6);
	this->theThreadParament.dwTimeOut=this->dwTimeOutValue;
	pMainWindow->SendMessage(WM_BEGIN_SCAN,ARP_FAST_SCAN,(LPARAM)&(this->theThreadParament));
}

BOOL CArpScanDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// TODO:  �ڴ���Ӷ���ĳ�ʼ��

	UCHAR *p=(UCHAR *)&(this->dwLocalIP);
	memset(&(this->theThreadParament),0,sizeof(this->theThreadParament));
	this->strLocalIp.Format("%d.%d.%d.%d",p[3],p[2],p[1],p[0]);
	p=(UCHAR *)&(this->dwNetMask);
	this->strNetMask.Format("%d.%d.%d.%d",p[3],p[2],p[1],p[0]);
	p=(UCHAR *)&(this->dwDefaultGateway);
	this->strDefaultGateway.Format("%d.%d.%d.%d",p[3],p[2],p[1],p[0]);
	this->strHostMAc.Format("%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",this->bLocalMac[0],this->bLocalMac[1],this->bLocalMac[2],this->bLocalMac[3],this->bLocalMac[4],this->bLocalMac[5]);
	this->UpdateData(false);
	return TRUE;  // return TRUE unless you set the focus to a control
	// �쳣: OCX ����ҳӦ���� FALSE
}

void CArpScanDlg::OnOK()
{
	// TODO: �ڴ����ר�ô����/����û���
	this->OnBnClickedSlowScan();
	//CDialog::OnOK();
}
