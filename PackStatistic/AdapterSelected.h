#if !defined(AFX_ADAPTERSELECTED_H__45E7C233_AB99_41B3_B168_5B4BF52EF76F__INCLUDED_)
#define AFX_ADAPTERSELECTED_H__45E7C233_AB99_41B3_B168_5B4BF52EF76F__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// AdapterSelected.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// CAdapterSelected dialog

class CAdapterSelected : public CDialog
{
// Construction
public:
	int select;				//选择的网卡
	CString filter;			//过滤规则
	CAdapterSelected(CWnd* pParent = NULL);   // standard constructor

// Dialog Data
	//{{AFX_DATA(CAdapterSelected)
	enum { IDD = IDD_PROTOCOLANALYZER_DIALOG1 };
	CEdit	m_filter;
	CComboBox	m_list;
	//}}AFX_DATA


// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CAdapterSelected)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:

	// Generated message map functions
	//{{AFX_MSG(CAdapterSelected)
	virtual BOOL OnInitDialog();
	afx_msg void OnOK();
	afx_msg void OnCancel();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_ADAPTERSELECTED_H__45E7C233_AB99_41B3_B168_5B4BF52EF76F__INCLUDED_)
