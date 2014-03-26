#pragma once

#include <pcap.h>

// CChoose �Ի���

class CChoose : public CDialog
{
	DECLARE_DYNAMIC(CChoose)

public:
	CChoose(pcap_if_t * DevHeader,CWnd* pParent);   // ��׼���캯��
	virtual ~CChoose();

// �Ի�������
	enum { IDD = IDD_CHOOSE_ADAPTOR };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
	CComboBox ComboCtrl;
	int CurrentSel;
	pcap_if_t * DevHeader;

	virtual BOOL OnInitDialog();
};
