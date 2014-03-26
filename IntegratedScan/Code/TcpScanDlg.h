#pragma once
#include "afxwin.h"


// CTcpScanDlg 对话框

class CTcpScanDlg : public CDialog
{
	DECLARE_DYNAMIC(CTcpScanDlg)

public:
	CTcpScanDlg(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CTcpScanDlg();

// 对话框数据
	enum { IDD = IDD_TCP_SCAN };
	SCAN_TYPE emScanType;//用户选定的扫描类型
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
protected:
	virtual void OnOK();
	DECLARE_MESSAGE_MAP()
public:
	
	afx_msg void OnBnClickedRadioConnectScan();
	afx_msg void OnBnClickedRadioSYNScan();
	afx_msg void OnBnClickedRadioFINScan();
	CEdit CTimeOutEditCtrl;
	short shTimeoutValue;
	bool bConnectScan;
	virtual BOOL OnInitDialog();
	afx_msg void OnBnClickedStartTcpScan();
	ThreadParament* pThreadParament;

	CWnd *pParamentConstructor;

	afx_msg void OnBnClickedRadioXMan();
	afx_msg void OnBnClickedRadioNull();
};
