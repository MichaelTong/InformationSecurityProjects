#pragma once
#include "afxwin.h"


// CTcpScanDlg �Ի���

class CTcpScanDlg : public CDialog
{
	DECLARE_DYNAMIC(CTcpScanDlg)

public:
	CTcpScanDlg(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CTcpScanDlg();

// �Ի�������
	enum { IDD = IDD_TCP_SCAN };
	SCAN_TYPE emScanType;//�û�ѡ����ɨ������
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��
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
