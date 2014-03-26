// Choose.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "BeastScaner.h"
#include "Choose.h"
// Choose.cpp : ʵ���ļ�


// CChoose �Ի���

IMPLEMENT_DYNAMIC(CChoose, CDialog)
CChoose::CChoose(pcap_if_t * DevHeader,CWnd* pParent /*=NULL*/)
	: CDialog(CChoose::IDD, pParent)
	, CurrentSel(0)
{
	this->DevHeader=DevHeader;
}

CChoose::~CChoose()
{
}

void CChoose::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO1, ComboCtrl);
}


BEGIN_MESSAGE_MAP(CChoose, CDialog)
	ON_BN_CLICKED(IDOK, OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, OnBnClickedCancel)
END_MESSAGE_MAP()


// CChoose ��Ϣ�������

void CChoose::OnBnClickedOk()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	this->UpdateData();
	this->CurrentSel=this->ComboCtrl.GetCurSel();
	OnOK();
}

void CChoose::OnBnClickedCancel()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	OnCancel();
}

BOOL CChoose::OnInitDialog()
{
	CDialog::OnInitDialog();

	// TODO:  �ڴ���Ӷ���ĳ�ʼ��
	pcap_if_t *d;
	char strName[64];
	gethostname(strName,64);
	hostent* pHostEnt;
    pHostEnt = gethostbyname(strName);

	DWORD dwLocalIP=unsigned long(pHostEnt->h_addr_list[0][0] & 0XFF)*0x1000000+unsigned long(pHostEnt->h_addr_list[0][1] & 0XFF)*0x10000+unsigned long(pHostEnt->h_addr_list[0][2] & 0XFF)*0x100+unsigned long(pHostEnt->h_addr_list[0][3] & 0XFF);
	int i=0;
	for(d=this->DevHeader;d;d=d->next)
	{
		this->ComboCtrl.InsertString(i,d->description);//.AddString(d->description);
		i++;
	}
	this->ComboCtrl.SetCurSel(i-1);

	return TRUE;  // return TRUE unless you set the focus to a control
	// �쳣: OCX ����ҳӦ���� FALSE
}
