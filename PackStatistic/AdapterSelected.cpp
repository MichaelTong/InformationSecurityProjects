// AdapterSelected.cpp : implementation file
//

#include "stdafx.h"
#include "ProtocolAnalyzer.h"
#include "AdapterSelected.h"
#include <pcap.h>
#pragma comment(lib, "wpcap")

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

extern pcap_if_t *alldevs;
extern char errbuf[PCAP_ERRBUF_SIZE+1];
extern pcap_t * pAdptHandle;				
extern pcap_if_t *pDevGlobal;
/////////////////////////////////////////////////////////////////////////////
// CAdapterSelected dialog


CAdapterSelected::CAdapterSelected(CWnd* pParent /*=NULL*/)
	: CDialog(CAdapterSelected::IDD, pParent)
{
	//{{AFX_DATA_INIT(CAdapterSelected)
		// NOTE: the ClassWizard will add member initialization here
	//}}AFX_DATA_INIT
}


void CAdapterSelected::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CAdapterSelected)
	DDX_Control(pDX, IDC_EDIT1, m_filter);
	DDX_Control(pDX, IDC_COMBO1, m_list);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CAdapterSelected, CDialog)
	//{{AFX_MSG_MAP(CAdapterSelected)
	ON_BN_CLICKED(IDC_BUTTON1, OnOK)
	ON_BN_CLICKED(IDC_BUTTON2, OnCancel)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CAdapterSelected message handlers

BOOL CAdapterSelected::OnInitDialog() 
{
	CDialog::OnInitDialog();
	
	// TODO: Add extra initialization here

	int num=0;			//��������

	pcap_if_t *pDev;
	pcap_findalldevs(&alldevs,errbuf);

	for(pDev=alldevs;pDev;pDev=pDev->next)
	{
		//���������
		if((pAdptHandle=pcap_open_live(pDev->name,65535,1,300,errbuf))==NULL)
		{
			MessageBox("�޷���������!");
			pcap_freealldevs(alldevs);
			return TRUE;
		}
		m_list.InsertString(num,_T(pDev->description));
		num++;
	}
	if (select>=0)
	{
		//ѡ������
		m_list.SetCurSel(select);
	}
	//���˹���
	m_filter.SetWindowText(filter);

	return TRUE;  // return TRUE unless you set the focus to a control
	              // EXCEPTION: OCX Property Pages should return FALSE
}

void CAdapterSelected::OnOK() 
{
	// TODO: Add your control notification handler code here
	select=m_list.GetCurSel();
	m_filter.GetWindowText(filter);
	if (select<0)
	{
		CDialog::OnOK();
		return;
	}
	//////////////////////////////////////////
	CString str;
	bool flag=false;
	m_list.GetLBText(select,str);	
	//�õ���ѡ�����������ָ��
	pcap_if_t *temp=0;
	for (temp=alldevs;temp;temp=temp->next)
	{
		if(CString(temp->description)==str)
		{
			flag=true;
			break;
		}
	}
	if(flag){
		pDevGlobal=temp;
	}
	else{
		MessageBox("û���ҵ���Ӧ��������!");
		pcap_freealldevs(alldevs);
		return ;
	}
	//����ѡ������
	if((pAdptHandle=pcap_open_live(pDevGlobal->name,65535,1,300,errbuf))==NULL)
	{
		MessageBox("�޷���������,������֮������");
		pcap_freealldevs(alldevs);
		return;
	}
	CDialog::OnOK();
}

void CAdapterSelected::OnCancel() 
{
	// TODO: Add your control notification handler code here
	CDialog::OnOK();

}

