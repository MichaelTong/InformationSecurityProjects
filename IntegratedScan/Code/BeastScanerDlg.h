// BeastScanerDlg.h : 头文件
//

#pragma once
#include "XTabCtrl.h"
#include "PortScanDlg.h"
#include "ArpScanDlg.h"
#include "IcmpScanDlg.h"
#include "afxwin.h"
#include "afxcmn.h"

// CBeastScanerDlg 对话框
class CBeastScanerDlg : public CDialog
{
// 构造
public:
	CBeastScanerDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_BEASTSCANER_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持

private:
	CButton cButtonPause;
// 实现
protected:
	HICON m_hIcon;
	pcap_if_t *alldevs,*SelectDev;
	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
	DWORD dwCurrentHostNo,dwCurrentPortInfoNo;
private:
	void GetLocalInfo(void);
	void InitListCtrl(void);
	void InitTabCtrl(void);
public:
	CXTabCtrl cTabCtrl;
	CPortScanDlg cPortScanDlg;
	CString stCurrentState;
	CArpScanDlg cArpScanDlg;
	CIcmpScanDlg cIcmpScanDlg;

	CListCtrl cListHostInfo;
	CListCtrl cListPortInfo;
	DWORD dwLocalIP;
	DWORD dwNetMask;
	DWORD dwDefaultGateway;
	UCHAR bLocalMac[6];
	SCAN_TYPE enCurrentScanType;
	afx_msg void OnBnClickedPause();
	afx_msg void OnBnClickedStop();
	afx_msg LRESULT OnBeginScan(WPARAM wparam,LPARAM lparam);
	afx_msg LRESULT OnAddHostInfo(WPARAM wprarm, LPARAM lprarm);
	afx_msg LRESULT OnFinishScan(WPARAM wparam,LPARAM lparam);	
	afx_msg LRESULT OnUpdataLog(WPARAM wparam,LPARAM lparam);
	afx_msg LRESULT OnHandleConnectScan(WPARAM wparam,LPARAM lparam);
	afx_msg LRESULT OnHandleUdpScan(WPARAM wparam,LPARAM lparam);
	afx_msg LRESULT OnHandleSynScan(WPARAM wparam,LPARAM lparam);
	afx_msg LRESULT OnHandleFinScan(WPARAM wparam,LPARAM lparam);
	afx_msg LRESULT OnHandleAckScan(WPARAM wparam,LPARAM lparam);
	afx_msg LRESULT OnHandleNullScan(WPARAM wparam,LPARAM lparam);
	afx_msg void OnNMDblclkListHostInfo(NMHDR *pNMHDR, LRESULT *pResult);

protected:
	virtual void OnOK();
public:
	afx_msg void OnDestroy();
	~CBeastScanerDlg(void);
};
