#pragma once


// CUdpScanDlg �Ի���

class CUdpScanDlg : public CDialog
{
	DECLARE_DYNAMIC(CUdpScanDlg)

public:
	CUdpScanDlg(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CUdpScanDlg();

// �Ի�������
	enum { IDD = IDD_UDP_SCAN };
protected:
	virtual void OnOK();
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	short shTimeoutValue;
	afx_msg void OnBnClickedUdpScan();

	ThreadParament *pThreadParament;

	CWnd *pParamentConstructor;
	DWORD dwTimeForOnePort;
	DWORD dwTimeBetweenToPackets;
};
