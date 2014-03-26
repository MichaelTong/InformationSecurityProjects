#pragma once

#include <pcap.h>

// CChoose 对话框

class CChoose : public CDialog
{
	DECLARE_DYNAMIC(CChoose)

public:
	CChoose(pcap_if_t * DevHeader,CWnd* pParent);   // 标准构造函数
	virtual ~CChoose();

// 对话框数据
	enum { IDD = IDD_CHOOSE_ADAPTOR };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
	CComboBox ComboCtrl;
	int CurrentSel;
	pcap_if_t * DevHeader;

	virtual BOOL OnInitDialog();
};
