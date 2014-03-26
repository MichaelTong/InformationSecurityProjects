#pragma once
#include "stdafx.h"


// CIcmpScanDlg 对话框

class CIcmpScanDlg : public CDialog
{
	DECLARE_DYNAMIC(CIcmpScanDlg)

public:
	CIcmpScanDlg(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CIcmpScanDlg();

// 对话框数据
	enum { IDD = IDD_ICMP_SCAN };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
protected:
	virtual void OnOK();
	SCAN_TYPE enCurrentScan;
	DECLARE_MESSAGE_MAP()
public:
	DWORD dwOriginateIPAddress;
	DWORD dwLastIPAddress;
	afx_msg void OnBnClickedNormalScan();
	afx_msg void OnBnClickedAdavncedScan();
	ThreadParament theThreadParament;
	DWORD dwTimeoutValue;

	afx_msg void OnBnClickedRadioWrongIpPacket();
	afx_msg void OnBnClickedRadioIpReorganization();
	afx_msg void OnBnClickedRadioWrongProtocol();
	virtual BOOL OnInitDialog();
};
