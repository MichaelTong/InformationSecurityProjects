#pragma once

// CPortScanDlg �Ի���
#include "TcpScanDlg.h"
#include "UdpScanDlg.h"
#include "xtabctrl.h"
#include "afxcmn.h"
#include "afxwin.h"
#include "stdafx.h"
class CPortScanDlg : public CDialog
{
	DECLARE_DYNAMIC(CPortScanDlg)

public:
	CPortScanDlg(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CPortScanDlg();

// �Ի�������
	enum { IDD = IDD_PORT_SCAN };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��
	
	DECLARE_MESSAGE_MAP()
public:
	CXTabCtrl cTabCtrl;
	CTcpScanDlg cTcpScanDlg;
	CUdpScanDlg cUdpScanDlg;
	virtual BOOL OnInitDialog();

	afx_msg void OnBnClickedSingleIP();
	afx_msg void OnBnClickedSinglePort();
	BOOL bSingleIP;
	BOOL bSinglePort;
	CIPAddressCtrl cIPAddressCtrl;
	CEdit cLastPortCtrl;
	DWORD dwOriginateIP;
	DWORD dwLastIP;

	DWORD dwLastPort;
	DWORD dwOriginatePort;
	ThreadParament theThreadParament;
	afx_msg LRESULT OnConstructParament(WPARAM wp,LPARAM lp);
protected:
	virtual void OnOK();
};
