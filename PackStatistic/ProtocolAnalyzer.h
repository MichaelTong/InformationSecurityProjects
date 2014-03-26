// ProtocolAnalyzer.h : main header file for the PROTOCOLANALYZER application
//

#if !defined(AFX_PROTOCOLANALYZER_H__E5608448_FCAE_441F_8A6C_200BBF0A04E8__INCLUDED_)
#define AFX_PROTOCOLANALYZER_H__E5608448_FCAE_441F_8A6C_200BBF0A04E8__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"		// main symbols

/////////////////////////////////////////////////////////////////////////////
// CProtocolAnalyzerApp:
// See ProtocolAnalyzer.cpp for the implementation of this class
//

class CProtocolAnalyzerApp : public CWinApp
{
public:
	CProtocolAnalyzerApp();

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CProtocolAnalyzerApp)
	public:
	virtual BOOL InitInstance();
	//}}AFX_VIRTUAL

// Implementation

	//{{AFX_MSG(CProtocolAnalyzerApp)
		// NOTE - the ClassWizard will add and remove member functions here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};


/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_PROTOCOLANALYZER_H__E5608448_FCAE_441F_8A6C_200BBF0A04E8__INCLUDED_)
