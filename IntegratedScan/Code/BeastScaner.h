// BeastScaner.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error �ڰ������� PCH �Ĵ��ļ�֮ǰ������stdafx.h��
#endif

#include "resource.h"		// ������


// CBeastScanerApp:
// �йش����ʵ�֣������ BeastScaner.cpp
//

class CBeastScanerApp : public CWinApp
{
public:
	CBeastScanerApp();

// ��д
	public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CBeastScanerApp theApp;