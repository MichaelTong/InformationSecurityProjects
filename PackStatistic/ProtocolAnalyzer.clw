; CLW file contains information for the MFC ClassWizard

[General Info]
Version=1
LastClass=CProtocolAnalyzerDlg
LastTemplate=CDialog
NewFileInclude1=#include "stdafx.h"
NewFileInclude2=#include "ProtocolAnalyzer.h"

ClassCount=4
Class1=CProtocolAnalyzerApp
Class2=CProtocolAnalyzerDlg
Class3=CAboutDlg

ResourceCount=5
Resource1=IDD_ABOUTBOX
Resource2=IDR_MAINFRAME
Resource3=IDD_PROTOCOLANALYZER_DIALOG1
Resource4=IDD_PROTOCOLANALYZER_DIALOG
Class4=CAdapterSelected
Resource5=IDR_MENU1

[CLS:CProtocolAnalyzerApp]
Type=0
HeaderFile=ProtocolAnalyzer.h
ImplementationFile=ProtocolAnalyzer.cpp
Filter=N

[CLS:CProtocolAnalyzerDlg]
Type=0
HeaderFile=ProtocolAnalyzerDlg.h
ImplementationFile=ProtocolAnalyzerDlg.cpp
Filter=D
LastObject=CProtocolAnalyzerDlg
BaseClass=CDialog
VirtualFilter=dWC

[CLS:CAboutDlg]
Type=0
HeaderFile=ProtocolAnalyzerDlg.h
ImplementationFile=ProtocolAnalyzerDlg.cpp
Filter=D

[DLG:IDD_ABOUTBOX]
Type=1
Class=CAboutDlg
ControlCount=4
Control1=IDC_STATIC,static,1342177283
Control2=IDC_STATIC,static,1342308480
Control3=IDC_STATIC,static,1342308352
Control4=IDOK,button,1342373889

[DLG:IDD_PROTOCOLANALYZER_DIALOG]
Type=1
Class=CProtocolAnalyzerDlg
ControlCount=4
Control1=IDC_LIST1,SysListView32,1350631425
Control2=IDC_TREE1,SysTreeView32,1350632455
Control3=IDC_EDIT1,edit,1352732676
Control4=IDC_EDIT2,edit,1353781380

[DLG:IDD_PROTOCOLANALYZER_DIALOG1]
Type=1
Class=CAdapterSelected
ControlCount=7
Control1=IDC_STATIC,button,1342177287
Control2=IDC_COMBO1,combobox,1344340226
Control3=IDC_STATIC,button,1342177287
Control4=IDC_STATIC,static,1342308352
Control5=IDC_EDIT1,edit,1350631552
Control6=IDC_BUTTON1,button,1342242816
Control7=IDC_BUTTON2,button,1342242816

[MNU:IDR_MENU1]
Type=1
Class=CProtocolAnalyzerDlg
Command1=ID_MENUITEM32771
Command2=ID_MENUITEM32772
Command3=ID_MENUITEM32773
Command4=ID_MENUITEM32774
CommandCount=4

[CLS:CAdapterSelected]
Type=0
HeaderFile=AdapterSelected.h
ImplementationFile=AdapterSelected.cpp
BaseClass=CDialog
Filter=D
LastObject=CAdapterSelected
VirtualFilter=dWC

