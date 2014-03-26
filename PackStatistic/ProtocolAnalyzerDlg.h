// ProtocolAnalyzerDlg.h : header file
//

#if !defined(AFX_PROTOCOLANALYZERDLG_H__D27F5503_9230_4D10_8373_6C6C9189591B__INCLUDED_)
#define AFX_PROTOCOLANALYZERDLG_H__D27F5503_9230_4D10_8373_6C6C9189591B__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
#include "AdapterSelected.h"
/////////////////////////////////////////////////////////////////////////////
// CProtocolAnalyzerDlg dialog

class CProtocolAnalyzerDlg : public CDialog
{
// Construction
public:
	void ShowApplicationsView(char *data,int len);
	void ShowDataView(char* data,int len);
	void ShowContentView(char* data,int len,int row);
	void GetProtocolPacket();
	CAdapterSelected adapterSelected;
	int select;//选择的网卡
	BOOL start;	//开始标记
	int listNum;	//list数量
	CProtocolAnalyzerDlg(CWnd* pParent = NULL);	// standard constructor
// Dialog Data
	//{{AFX_DATA(CProtocolAnalyzerDlg)
	enum { IDD = IDD_PROTOCOLANALYZER_DIALOG };
	CEdit	m_http;
	CTreeCtrl	m_tree;
	CEdit	m_data;
	CListCtrl	m_report;
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CProtocolAnalyzerDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	//{{AFX_MSG(CProtocolAnalyzerDlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnStartCapture();
	afx_msg void OnSetFilter();
	afx_msg void OnStopCapture();
	afx_msg void OnParticularContent(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnSortPacket(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnMenuitem32771();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_PROTOCOLANALYZERDLG_H__D27F5503_9230_4D10_8373_6C6C9189591B__INCLUDED_)
