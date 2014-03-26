// stdafx.cpp : 只包括标准包含文件的源文件
// BeastScaner.pch 将是预编译头
// stdafx.obj 将包含预编译类型信息

#include "stdafx.h"


CWnd * pMainWindow;//用来接收消息的窗口指针，本程序规模较小，故采用此全局变量保存信息！
bool bPause=false;//用来代表是否扫描暂停
bool bStop=false;
DWORD dwCurrentThreadNo=0;