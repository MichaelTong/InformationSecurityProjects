static int CALLBACK MyCompareProc0(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort) 
{ 
	//以第1列为根据排序 
	CListCtrl* pListCtrl = (CListCtrl*)lParamSort; 
	CString strItem1 = pListCtrl->GetItemText(lParam1, 0); 
	CString strItem2 = pListCtrl->GetItemText(lParam2, 0); 
	//比较两个数 
	LPCTSTR s1=(LPCTSTR)strItem1; 
	LPCTSTR s2=(LPCTSTR)strItem2; 	
	int n1=atoi(s1); 
	int n2=atoi(s2);	
	if (n1<n2) 
		return -1; 
	else  if(n1>n2)
		return 1; 
	else return 0;
} 
static int CALLBACK MyCompareProc1(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort) 
{ 
	//以第1列为根据排序 
	CListCtrl* pListCtrl = (CListCtrl*)lParamSort; 
	CString strItem1 = pListCtrl->GetItemText(lParam1, 0); 
	CString strItem2 = pListCtrl->GetItemText(lParam2, 0); 
	//比较两个数 
	LPCTSTR s1=(LPCTSTR)strItem1; 
	LPCTSTR s2=(LPCTSTR)strItem2; 	
	int n1=atoi(s1); 
	int n2=atoi(s2);	
	if (n1<n2) 
		return -1; 
	else  if(n1>n2)
		return 1; 
	else return 0;
} 
static int CALLBACK MyCompareProc2(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort) 
{ 
	//以第2列为根据排序 
	CListCtrl* pListCtrl = (CListCtrl*)lParamSort; 
	CString strItem1 = pListCtrl->GetItemText(lParam1, 2); 
	CString strItem2 = pListCtrl->GetItemText(lParam2, 2); 
	//比较两个字符串 
	LPCTSTR s1=(LPCTSTR)strItem1; 
	LPCTSTR s2=(LPCTSTR)strItem2; 	
	int i=stricmp(strItem1,strItem2); 
	if (i<0) 
		return -1; 
	else if(i>0)
		return 1;
	else return 0;
} 
static int CALLBACK MyCompareProc3(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort) 
{ 
	//以第3列为根据排序 
	CListCtrl* pListCtrl = (CListCtrl*)lParamSort; 
	CString strItem1 = pListCtrl->GetItemText(lParam1, 3); 
	CString strItem2 = pListCtrl->GetItemText(lParam2, 3); 
	//比较两个字符串
	int i=stricmp(strItem1,strItem2); 
	if (i<0) 
		return -1; 
	else if(i>0)
		return 1;
	else return 0;
} 
static int CALLBACK MyCompareProc4(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort) 
{ 
	//以第4列为根据排序 
	CListCtrl* pListCtrl = (CListCtrl*)lParamSort; 
	CString strItem1 = pListCtrl->GetItemText(lParam1, 4); 
	CString strItem2 = pListCtrl->GetItemText(lParam2, 4); 
	//比较两个字符串
	int i=stricmp(strItem1,strItem2); 
	if (i<0) 
		return -1; 
	else if(i>0)
		return 1;
	else return 0;
} 
static int CALLBACK MyCompareProc5(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort) 
{ 
	//以第5列为根据排序 
	CListCtrl* pListCtrl = (CListCtrl*)lParamSort; 
	CString strItem1 = pListCtrl->GetItemText(lParam1, 5); 
	CString strItem2 = pListCtrl->GetItemText(lParam2, 5); 
	//比较两个字符串
	int i=stricmp(strItem1,strItem2); 
	if (i<0) 
		return -1; 
	else if(i>0)
		return 1;
	else return 0;
} 
static int CALLBACK MyCompareProc6(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort) 
{ 
	//以第6列为根据排序 
	CListCtrl* pListCtrl = (CListCtrl*)lParamSort; 
	CString strItem1 = pListCtrl->GetItemText(lParam1, 6); 
	CString strItem2 = pListCtrl->GetItemText(lParam2, 6); 
	//比较两个字符串
	int i=stricmp(strItem1,strItem2); 
	if (i<0) 
		return -1; 
	else if(i>0)
		return 1;
	else return 0;
} 

static int CALLBACK MyCompareProc7(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort) 
{ 
	//以第7列为根据排序 
	CListCtrl* pListCtrl = (CListCtrl*)lParamSort; 
	CString strItem1 = pListCtrl->GetItemText(lParam1, 7); 
	CString strItem2 = pListCtrl->GetItemText(lParam2, 7); 
	//比较两个字符串
	int i=stricmp(strItem1,strItem2); 
	if (i<0) 
		return -1; 
	else if(i>0)
		return 1;
	else return 0;
} 

static int CALLBACK MyCompareProc8(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort) 
{ 
	//以第7列为根据排序 
	CListCtrl* pListCtrl = (CListCtrl*)lParamSort; 
	CString strItem1 = pListCtrl->GetItemText(lParam1, 8); 
	CString strItem2 = pListCtrl->GetItemText(lParam2, 8); 
	//比较两个数 
	LPCTSTR s1=(LPCTSTR)strItem1; 
	LPCTSTR s2=(LPCTSTR)strItem2; 	
	int n1=atoi(s1); 
	int n2=atoi(s2);	
	if (n1<n2) 
		return -1; 
	else  if(n1>n2)
		return 1; 
	else return 0;
} 