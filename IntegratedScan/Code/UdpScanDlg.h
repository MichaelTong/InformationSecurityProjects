#pragma once


// CUdpScanDlg 对话框

class CUdpScanDlg : public CDialog
{
	DECLARE_DYNAMIC(CUdpScanDlg)

public:
	CUdpScanDlg(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CUdpScanDlg();

// 对话框数据
	enum { IDD = IDD_UDP_SCAN };
protected:
	virtual void OnOK();
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	short shTimeoutValue;
	afx_msg void OnBnClickedUdpScan();

	ThreadParament *pThreadParament;

	CWnd *pParamentConstructor;
	DWORD dwTimeForOnePort;
	DWORD dwTimeBetweenToPackets;
};
