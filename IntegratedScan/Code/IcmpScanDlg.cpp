// IcmpScanDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "BeastScaner.h"
#include "IcmpScanDlg.h"
#include ".\icmpscandlg.h"


// CIcmpScanDlg �Ի���

IMPLEMENT_DYNAMIC(CIcmpScanDlg, CDialog)
CIcmpScanDlg::CIcmpScanDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CIcmpScanDlg::IDD, pParent)
	, dwOriginateIPAddress(0)
	, dwLastIPAddress(0)
	, dwTimeoutValue(2)
	, enCurrentScan(NO_SCAN)
{
	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD(1, 1);
	::WSAStartup(wVersionRequested, &wsaData);
	memset(&(this->theThreadParament),0,sizeof(this->theThreadParament));

}

CIcmpScanDlg::~CIcmpScanDlg()
{
	::WSACleanup();
}

void CIcmpScanDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_IPAddress(pDX, IDC_IPADDRESS1, dwOriginateIPAddress);
	DDX_IPAddress(pDX, IDC_IPADDRESS2, dwLastIPAddress);
	DDX_Text(pDX, IDC_EDIT1, dwTimeoutValue);
	DDV_MinMaxUInt(pDX, dwTimeoutValue, 1, 30);
}


BEGIN_MESSAGE_MAP(CIcmpScanDlg, CDialog)
	ON_BN_CLICKED(IDC_BUTTON1, OnBnClickedNormalScan)
	ON_BN_CLICKED(IDC_BUTTON2, OnBnClickedAdavncedScan)
	ON_BN_CLICKED(IDC_RADIO1, OnBnClickedRadioWrongIpPacket)
	ON_BN_CLICKED(IDC_RADIO3, OnBnClickedRadioIpReorganization)
	ON_BN_CLICKED(IDC_RADIO2, OnBnClickedRadioWrongProtocol)
END_MESSAGE_MAP()


// CIcmpScanDlg ��Ϣ�������

void CIcmpScanDlg::OnBnClickedNormalScan()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	this->UpdateData();
	this->theThreadParament.dwTimeOut=this->dwTimeoutValue;
	this->theThreadParament.dwOriginalIP=this->dwOriginateIPAddress;
	this->theThreadParament.dwLastIP=this->dwLastIPAddress;
	pMainWindow->SendMessage(WM_BEGIN_SCAN,ICMP_SCAN,(LPARAM)&(this->theThreadParament));
}

void CIcmpScanDlg::OnBnClickedAdavncedScan()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	this->UpdateData();
	this->theThreadParament.dwTimeOut=this->dwTimeoutValue;
	this->theThreadParament.dwOriginalIP=this->dwOriginateIPAddress;
	this->theThreadParament.dwLastIP=this->dwLastIPAddress;
	pMainWindow->SendMessage(WM_BEGIN_SCAN,this->enCurrentScan,(LPARAM)&(this->theThreadParament));
}

void CIcmpScanDlg::OnOK()
{
	this->OnBnClickedNormalScan();
}

void CIcmpScanDlg::OnBnClickedRadioWrongIpPacket()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	this->enCurrentScan=ICMP_WRONG_PORT_SCAN;
}
void CIcmpScanDlg::OnBnClickedRadioIpReorganization()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	this->enCurrentScan=ICMP_IP_REORGANIZATION_SCAN;
}

void CIcmpScanDlg::OnBnClickedRadioWrongProtocol()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	this->enCurrentScan=ICMP_WRONG_PROTOCOL_SCAN; 
}

BOOL CIcmpScanDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// TODO:  �ڴ���Ӷ���ĳ�ʼ��
	((CButton *)GetDlgItem(IDC_RADIO1))->SetCheck(TRUE);//ѡ��
	this->enCurrentScan=ICMP_WRONG_PORT_SCAN;
	return TRUE;  // return TRUE unless you set the focus to a control
	// �쳣: OCX ����ҳӦ���� FALSE
}
