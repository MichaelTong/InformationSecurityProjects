// BeastScanerDlg.h : ͷ�ļ�
//

#pragma once
#include "XTabCtrl.h"
#include "PortScanDlg.h"
#include "ArpScanDlg.h"
#include "IcmpScanDlg.h"
#include "afxwin.h"
#include "afxcmn.h"

// CBeastScanerDlg �Ի���
class CBeastScanerDlg : public CDialog
{
// ����
public:
	CBeastScanerDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_BEASTSCANER_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��

private:
	CButton cButtonPause;
// ʵ��
protected:
	HICON m_hIcon;
	pcap_if_t *alldevs,*SelectDev;
	// ���ɵ���Ϣӳ�亯��
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
