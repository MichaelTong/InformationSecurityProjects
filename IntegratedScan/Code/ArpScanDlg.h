#pragma once
#include "stdafx.h"


// CArpScanDlg 对话框

class CArpScanDlg : public CDialog
{
	DECLARE_DYNAMIC(CArpScanDlg)

public:
	CArpScanDlg(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CArpScanDlg();

// 对话框数据
	enum { IDD = IDD_ARP_SCAN };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	CString strHostMAc;
	//CString strHostIPAddress;
	afx_msg void OnBnClickedSlowScan();
	afx_msg void OnBnClickedFastScan();
	DWORD dwLocalIP;
	UCHAR bLocalMac[6];
	virtual BOOL OnInitDialog();
	ThreadParament theThreadParament;
protected:
	virtual void OnOK();
public:
	CString strHostName;
	DWORD dwTimeOutValue;
	DWORD dwNetMask;
	DWORD dwDefaultGateway;
	CString strLocalIp;
	CString strNetMask;
	CString strDefaultGateway;
};
