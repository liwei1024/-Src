/*
*	dll 劫持工具
*	2016-5-24
*	1.直接生产劫持对象文件 2.侦察可能劫持成功的对象(获取运行中的进程，列出其dll 选择劫持)
*/
#include "resource.h"
#include<windows.h>
#include<stdio.h>
#include <shlobj.h>    
#include<commctrl.h>
#include<TlHelp32.h>
#pragma comment(lib,"shell32.lib") //SHGetSpecialFolderPath函数用到

///////////////////////////////////////////////////////////////////////////////////////////////////
//数据结构
struct stString				//存储dll名称的链表 为什么不用二维数组？强迫症啊，
{
	CHAR szName[MAX_PATH];
	CHAR szPath[MAX_PATH];
	struct stString * next;
};
typedef struct stString STSTRING, *PSTSTRING;
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//窗口过程声明
INT_PTR CALLBACK MainDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK Sub1DlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK Sub2DlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

//功能: 相关初始化 减少MainDlgProc的臃肿
void Init(HWND hdlg,UINT msg,WPARAM wParam,LPARAM lParam);

//功能:获取目标文件全路径
BOOL GetFilePath(PCHAR pszDllPath);	

//功能:打开文件，获取dll文件路径，编辑框显示文件全路径
VOID Open();

//功能:获取保存目标文件全路径,编辑框显示保存后的路径
VOID Save();

//功能:获取保存目标文件全路径
BOOL SaveFilePath(PCHAR pszCFilePath);

//功能:切换到侦察模式
VOID HijactDll_DetectMode();

//功能:根据目标导出表生产dll劫持的.c文件
BOOL CreateDllSrc(PCSTR pszDllName,PCSTR pszSrcName);

//功能：把字符串插入链表
BOOL InsertName(PSTSTRING *pLink, PCSTR pszName);	

//功能初始化进程列标题
BOOL SetColumn_Process(HANDLE hProcessListContorl);

//功能:枚举进程到列表中
BOOL ShowProcess(HANDLE hList_View);

//功能:获取选中的进程ID
DWORD GetSelectProcessId(DWORD select);

//初始化DLL列标题;
BOOL SetColumn_Dll(HANDLE hDllListContorl); 

//功 能:显示可能被劫持的DLL
BOOL ShowDll(HANDLE hList_View, DWORD pid);

//功能:通过注册表 "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs" 获取knowndlls
PSTSTRING GetKnowndllsNameList();


///////////////////////////////////////////////////////////////////////////////////////////////////



///////////////////////////////////////////////////////////////////////////////////////////////////
//全局变量
CHAR szDllFileName[MAX_PATH];  //目标dll全路径
TCHAR wszDllFileName[MAX_PATH];  //目标dll全路径
CHAR szCFileName[MAX_PATH];    //存储目标路径
HWND hdlg = NULL;			   //对话框句柄
HINSTANCE hint;				   //实例句柄
HANDLE hProcessListContorl = NULL;				//显示进程列表框句柄
HANDLE hDllListContorl = NULL;				    //显示Dll列表框句柄
HWND hdlg2 = NULL;								//显示进程列表窗口的对话框句柄
DWORD dwProcessId = 0;							//进程ID
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//主函数
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPreInstance, LPSTR lpCmdLine, int nCmdShow)
{
	hint = hInstance;
	//创建窗口
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_MAIN), NULL, MainDlgProc);//最后一个就是窗口过程,消息循环它自己有了，我们只要自己写窗口过程

}
///////////////////////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////////////////////
//主对话框过程
INT_PTR CALLBACK MainDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	CHAR szTemp[MAX_PATH] = { 0 };
	DWORD dwRadioId = 0;
	hdlg = hDlg;											    		 //赋值全局变量，保存对话框句柄
	switch (message)
	{

	case WM_INITDIALOG:
		//窗口初始化操作
		Init(hDlg, message, wParam, lParam);
		break;
	case WM_COMMAND:
		//控件响应 LOWORD(wParam) 这个值是控件的ID
		switch (LOWORD(wParam))
		{
			//操作方式
		case IDC_OPENDLL:
		case IDC_DETECTDLL:
			dwRadioId = LOWORD(wParam);									//保存Radio ID
			if (dwRadioId == IDC_OPENDLL)								//说明选中打开DLL
				HijactDll_DetectMode(TRUE);
			else													    //说明选中侦察DLL
				HijactDll_DetectMode(FALSE);
			break;
			//打开文件
		case IDC_1_3:
			Open();
			break;
			//设置输出路径
		case IDC_1_6:
			Save();
			break;
		case IDC_CREATE:
			if (!CreateDllSrc(szDllFileName, szCFileName))
				MessageBoxA(hDlg, "生成目标文件失败", "错误", MB_OK);
			else
				MessageBoxA(hDlg, "生成目标文件成功", "恭喜", MB_OK);
			break;
		case IDC_2_1:
			DialogBoxParamA(hint, MAKEINTRESOURCEA(IDD_2_PROCESSLIST), hDlg, Sub1DlgProc, (LPARAM)0); //dwInitParam：指定传递到对话框过程中的 WM_INITDIALOG 消息 IParam 参数的值。
			break;
		}
		break;
	case WM_CLOSE:
		EndDialog(hDlg, 0);
		break;
	case WM_DESTROY:
		PostQuitMessage(0);

	}
	return FALSE;
}
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//进程列表对话框过程
INT_PTR CALLBACK Sub1DlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	hdlg2 = hDlg;
	DWORD dwSelect = -1; //标记选中的行
	switch (message)
	{


	case WM_INITDIALOG:
		//获取列表控件句柄
		hProcessListContorl = GetDlgItem(hDlg, IDC_PROCESSLIST); 
		 //初始化进程列标题
		SetColumn_Process( hProcessListContorl);    
		//显示进程到列表控件
		 ShowProcess(hProcessListContorl);
		break;
	case WM_COMMAND:

		//控件响应 LOWORD(wParam) 这个值是控件的ID
		switch (LOWORD(wParam))
		{
			//取消
		case IDC_2_OUT:
			EndDialog(hDlg, 0);
			break;
			//查看DLL
		case IDC_2_BUTTON:
			//获取进程ID
			dwSelect = ListView_GetSelectionMark(hProcessListContorl);		//获取一个被选中的行 保存到iSelect 中 OK
			if (dwSelect == -1)
			{
				MessageBoxA(hDlg, "请选择一个进程", "提醒", MB_OK);
				return FALSE;
			}
			//隐藏
			ShowWindow(hDlg, FALSE);
			//创建窗口 传入参数为进程ID
			DialogBoxParamA(hint, MAKEINTRESOURCEA(IDD_2_DLL), hDlg, Sub2DlgProc, (LPARAM)GetSelectProcessId(dwSelect)); //dwInitParam：指定传递到对话框过程中的 WM_INITDIALOG 消息 IParam 参数的值。
			break;
	
		}
		break;
	case WM_CLOSE:

		EndDialog(hDlg, 0);

		break;

	}

	return FALSE;
}
///////////////////////////////////////////////////////////////////////////////////////////////////




///////////////////////////////////////////////////////////////////////////////////////////////////
//DLL列表对话框过程
INT_PTR CALLBACK Sub2DlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{

	DWORD dwSelect = -1; //标记选中的行
	switch (message)
	{


	case WM_INITDIALOG:
		//设置默认路径
		SetDlgItemTextA(hDlg, IDC_2_SAVEPATH, szCFileName);
		dwProcessId = (DWORD)lParam;
		//获取列表控件句柄
		hDllListContorl = GetDlgItem(hDlg, IDC_DLLLIST);
		//初始化DLL列标题
		SetColumn_Dll( hDllListContorl);     //初始化DLL列标题;
		//显示非knowndlls中的dll到列表控件中
		ShowDll(hDllListContorl, dwProcessId);
		break;
	case WM_COMMAND:

		//控件响应 LOWORD(wParam) 这个值是控件的ID
		switch (LOWORD(wParam))
		{
		case IDC_2_CREATE:
			//获取选中的行
			dwSelect = ListView_GetSelectionMark(hDllListContorl);			//获取一个被选中的行 保存到dwSelect 中 OK
			if (dwSelect == -1)
			{
				MessageBoxA(hDlg, "请选择模块", "提醒", MB_OK);
				return FALSE;
			}
			ListView_GetItemText(hDllListContorl, dwSelect, 2, wszDllFileName, MAX_PATH); //获取第2列的内容保存到szDllFileName
			OutputDebugString(wszDllFileName);
			WideCharToMultiByte(CP_ACP, 0, wszDllFileName, _countof(wszDllFileName), szDllFileName, MAX_PATH, NULL, 0);
				
			if (!CreateDllSrc(szDllFileName, szCFileName))
				MessageBoxA(hDlg, "生成目标文件失败", "错误", MB_OK);
			else
				MessageBoxA(hDlg, "生成目标文件成功", "恭喜", MB_OK);
			break;
		case IDC_2_GETPATH:
			if (SaveFilePath(szCFileName))
				SetDlgItemTextA(hDlg, IDC_2_SAVEPATH, szCFileName);
			break;
		}
		break;
	case WM_CLOSE:
		ShowWindow(hdlg2, TRUE);
		EndDialog(hDlg, 0);

		break;

	}

	return FALSE;
}
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//功能: 相关初始化 减少MainDlgProc的臃肿
void Init(HWND hdlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	CheckRadioButton(hdlg, IDC_OPENDLL, IDC_DETECTDLL, IDC_OPENDLL); //开始的时候选择第一个
	ShowWindow(GetDlgItem(hdlg, IDC_2_1), FALSE);					 //隐藏开始控件
	//初始化生产文件默认路径  为 桌面/FakeLib.c
	SHGetSpecialFolderPathA(NULL, szCFileName, CSIDL_DESKTOP, FALSE);
	strcat_s(szCFileName, MAX_PATH, "\\FakeLib.c");
	SetDlgItemTextA(hdlg, IDC_1_5, szCFileName);
}
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//功  能:获取目标文件全路径
//参  数:接收全路径文件名 
//返回值:失败返回FALSE
BOOL GetFilePath(PCHAR pszDllPath)
{
	//过滤
	CHAR szFileFilter[] = "dll files(*.dll)\0*.dll\0\0"; //第一个字符串是过滤器描述的显示字符串（例如，“文本文件”），第二个字符指定过滤样式（例如，“*.TXT”）
	OPENFILENAMEA ofn;
	//初始化
	ZeroMemory(&ofn, sizeof(ofn));						//初始化 为空
	ZeroMemory(pszDllPath, MAX_PATH);					//初始化 为空
	//结构体成员设置
	ofn.lStructSize = sizeof(ofn);						//结构体大小要写
	ofn.hwndOwner = NULL;								//指定它的父窗口，指定它的父窗口一般为NULL，表示我们使用的是通用对话框
	ofn.lpstrFile = pszDllPath;							//用于保存文件的完整路径及文件名
	ofn.lpstrFilter = szFileFilter;						//过滤类型
	ofn.nMaxFile = MAX_PATH;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;  
	if (!GetOpenFileNameA(&ofn))
		return FALSE;
	//成功
	return TRUE;
}
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//功能:打开文件，获取dll文件路径，编辑框显示文件全路径
VOID Open()
{
	if (!GetFilePath(szDllFileName))
		MessageBoxA(hdlg, "获取目标文件失败", "错误", MB_OK);
	else
		SetDlgItemTextA(hdlg, IDC_1_2, szDllFileName);
}
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//功能:获取保存目标文件全路径,编辑框显示保存后的路径
VOID Save()
{
	if (!SaveFilePath(szCFileName))
		MessageBoxA(hdlg, "错误文件名", "错误", MB_OK);
	else
		SetDlgItemTextA(hdlg, IDC_1_5, szCFileName);
}
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//功  能:保存目标文件全路径
//参  数:接受保存路径文件名
//返回值:失败返回FALSE
BOOL SaveFilePath(PCHAR pszCFilePath)
{
	CHAR szFileFilter[] = "dll files(*.c)\0*.c\0\0"; //第一个字符串是过滤器描述的显示字符串（例如，“文本文件”），第二个字符指定过滤样式（例如，“*.TXT”）
	OPENFILENAMEA ofn;
	//初始化
	ZeroMemory(&ofn, sizeof(ofn));					//初始化 为空
	ZeroMemory(pszCFilePath, MAX_PATH);				//初始化 为空
	//结构体成员设置
	ofn.lStructSize = sizeof(ofn);					//结构体大小要写
	ofn.hwndOwner = NULL;							//指定它的父窗口，指定它的父窗口一般为NULL，表示我们使用的是通用对话框
	ofn.lpstrFile = pszCFilePath;					// 用于保存文件的完整路径及文件名
	ofn.lpstrFilter = szFileFilter;				    //过滤类型
	ofn.nMaxFile = MAX_PATH;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST; 
	if (!GetSaveFileNameA(&ofn))
		return FALSE;
	//.c文件后缀
	strcat_s(pszCFilePath, MAX_PATH, ".c");
	return TRUE;
}
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//功能:切换到侦察模式
//参数:传TURE为直接打开DLL文件模式，FALSE为侦察模式
VOID HijactDll_DetectMode(BOOL bFalg)
{
	SetWindowTextA(GetDlgItem(hdlg, IDC_GROUP2), "进程");
	//隐藏打开方式的所有控件
	for (int i = IDC_1_1; i <= IDC_1_6; i++)
		ShowWindow(GetDlgItem(hdlg, i), bFalg);
	ShowWindow(GetDlgItem(hdlg, IDC_CREATE), bFalg);
	//显示侦察方式的所有控件
	ShowWindow(GetDlgItem(hdlg, IDC_2_1), !bFalg);
}
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//功  能：把字符串插入链表
//参  数：1.链表指针 2.要插入的字符串
//返回值：失败返回FALSE,失败的原因可能是因为内存分配失败
BOOL InsertName(PSTSTRING *pLink, PCSTR pszName)
{
	PSTSTRING pTail = NULL;
	PSTSTRING pTemp = NULL;
	//申请新的节点
	pTemp = (PSTSTRING)VirtualAlloc(NULL, sizeof(STSTRING), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pTemp == NULL)
	{
		OutputDebugStringA("动态分配内存失败");
		return FALSE;
	}
	//初始化新申请的节点
	ZeroMemory(pTemp->szName, MAX_PATH);
	pTemp->next = NULL;

	if (*pLink == NULL)			//第一次插入字符串操作
	{

		*pLink = pTemp;
		strcpy_s(pTemp->szName, MAX_PATH, pszName);

	}
	else
	{

		//不是第一次
		pTail = *pLink;
		while (pTail->next != NULL) //移动到最后一个节点
			pTail = pTail->next;
		pTail->next = pTemp;
		strcpy_s(pTemp->szName, MAX_PATH, pszName);
	}
	return TRUE;
}
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//功  能:根据目标pe导出表生产dll劫持的.c文件
//参  数:1,目标文件路径 2.生成的c源代码文件路径
//返回值: 失败返回FALSE
BOOL CreateDllSrc(PCSTR pszDllName, PCSTR pszSrcName)
{
	HANDLE hFile = NULL;	

	//第一步 打开文件
	hFile = CreateFileA(pszDllName, GENERIC_READ, 0, NULL, OPEN_EXISTING, (DWORD)NULL, (HANDLE)NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		OutputDebugStringA("打开DLL文件失败，\n");
		return FALSE;
	}
	
	//第二步 创建文件映射
	HANDLE hMap = NULL;
	hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, 0);   //注意对其SEC_IMAGE方式，选这个参数之后我们不用做FOA 和 RVA的转换了
	if (!hMap)
	{
		OutputDebugStringA("创建文件映射失败");;
		CloseHandle(hFile);
		return FALSE;
	}

	//第三步 映射到自己进程的空间
	LPVOID pMap = NULL;
	pMap = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);    //这时候pMap 就是DOS头了
	if (!pMap)
	{
		OutputDebugStringA("映射到进程失败");
		CloseHandle(hMap);
		CloseHandle(hFile);
		return FALSE;
	}

	//第四步 根据PE结构导出函数进行创建C源码文件操作
	PIMAGE_DOS_HEADER pDosHeader = NULL;				 //DOS 头指针
	PIMAGE_NT_HEADERS pPeHeader = NULL;					 //PE  头指针
	pDosHeader = (PIMAGE_DOS_HEADER)pMap;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)      //判断是否PE文件我这里只判断DOS头
	{
		OutputDebugStringA("不是PE文件");
		UnmapViewOfFile(pMap);
		CloseHandle(hMap);
		CloseHandle(hFile);
		return FALSE;
	}

	
	pPeHeader = (PIMAGE_NT_HEADERS)((DWORD)pMap + pDosHeader->e_lfanew);			//获得PE头文件指针
	//获取导出表VA地址
	PIMAGE_EXPORT_DIRECTORY  pExportDirectory;									    
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pMap + pPeHeader->OptionalHeader.DataDirectory[0].VirtualAddress);		

	//遍历导出表
	//由于全是命名方式，循环也只有一个选择
	DWORD FunctionNameRVA = 0;
	PDWORD pFunctionName = NULL;
	int iIndexAddressOfNameOrdinals = 0;

	//定义链表头
	PSTSTRING pLink = NULL;

	//指针真头疼，还要注意的是AddressOfNameOrdinals指向的是一个WORD数组，不是DWORD数字!!!
	//还有就是类型转换以及指针运算和类型宽度问题
	for (DWORD i = 0; i < (pExportDirectory->NumberOfFunctions); i++)
	{

		iIndexAddressOfNameOrdinals = *((WORD*)((DWORD)pExportDirectory->AddressOfNameOrdinals + (DWORD)pDosHeader) + i); //索号，要根据索获取函数地址
		FunctionNameRVA = *((DWORD*)((DWORD)pExportDirectory->AddressOfNames + (DWORD)pDosHeader + i * 4));
		//这时候pFunctionName指向导出函数名称
		pFunctionName = (PDWORD)(FunctionNameRVA + (DWORD)pDosHeader); 

		//把函数插入到链表中
		if (!InsertName(&pLink, (PCSTR)pFunctionName))
		{
			UnmapViewOfFile(pMap);
			CloseHandle(hMap);
			CloseHandle(hFile);
			return FALSE;
		}

	}
			
	////调试 输出链表 导出函数获取ok
	//PSTSTRING ptemp = pLink;
	//while (ptemp != NULL)
	//{
	//	OutputDebugStringA(ptemp->szName);
	//	ptemp = ptemp->next;
	//}
	
	//创建目标文件
	HANDLE hCFile = NULL;
	hCFile = CreateFileA(pszSrcName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hCFile == INVALID_HANDLE_VALUE)
	{
		OutputDebugStringA("创建目标文件失败");
		UnmapViewOfFile(pMap);
		CloseHandle(hMap);
		CloseHandle(hFile);
		return FALSE;
	}



	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//开始写入文件
	CHAR szMyHead[20] = "JMP_";
	DWORD dwWritten = 0;
	CHAR szTemp[4096] = { 0 };
	sprintf_s(szTemp, sizeof(szTemp),

		"#include<windows.h>\r\n"
		"#include<stdio.h>\r\n\r\n\r\n"
		"////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////\r\n"
		"// 导出函数\r\n"
		);
	//写入固定部分
	if (!WriteFile(hCFile, szTemp, strlen(szTemp), &dwWritten, NULL))
	{
		OutputDebugStringA("写入文件失败");
		UnmapViewOfFile(pMap);
		CloseHandle(hMap);
		CloseHandle(hFile);
		CloseHandle(hCFile);
		return FALSE;
	}
	dwWritten = 0;

	//写入#pragma comment部分
	PSTSTRING pTemp = pLink;
	DWORD dwIndex = 1;
	while (pTemp != NULL)
	{
		ZeroMemory(szTemp, 4096);
		sprintf_s(szTemp, sizeof(szTemp), "#pragma comment(linker, \"/EXPORT:%s=_%s%s,@%d\")\r\n", pTemp->szName, szMyHead,pTemp->szName, dwIndex);
		pTemp = pTemp->next;
		dwIndex++;
		//写入
		if (!WriteFile(hCFile, szTemp, strlen(szTemp), &dwWritten, NULL))
		{
			OutputDebugStringA("写入文件失败");
			UnmapViewOfFile(pMap);
			CloseHandle(hMap);
			CloseHandle(hFile);
			CloseHandle(hCFile);
			return FALSE;
		}
		dwWritten = 0;
	}
	
	dwIndex--;

	
	//写入固定部分
	dwWritten = 0;
	ZeroMemory(szTemp, sizeof(szTemp));
	sprintf_s(szTemp,sizeof(szTemp), 
		"////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////\r\n\r\n\r\n\r\n\r\n"
		"////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////\r\n"
		"// 宏定义\r\n"
		"#define EXTERNC extern \"C\"\n"
		"#define NAKED __declspec(naked)\n"
		"#define EXPORT __declspec(dllexport)\n"

		"#define ALCPP EXPORT NAKED\n"
		"#define ALSTD EXTERNC EXPORT NAKED void __stdcall\n"
		"#define ALCFAST EXTERNC EXPORT NAKED void __fastcall\n"
		"#define ALCDECL EXTERNC NAKED void __cdecl\n"
		"////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////\r\n\r\n\r\n\r\n\r\n"
		"////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////\r\n"
		"//全局变量\r\n"
		"HMODULE hDll = NULL;\r\n"
		"DWORD dwRetaddress[%d];							//存放返回地址\r\n"
		"////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////\r\n\r\n\r\n\r\n\r\n"
		"////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////\r\n"
		"// 内部函数 获取真实函数地址\r\n"
		"FARPROC WINAPI GetAddress(PCSTR pszProcName)\r\n"
		"{\r\n"
			"\t\tFARPROC fpAddress;\r\n"
			"\t\tCHAR szTemp[MAX_PATH] = { 0 };\r\n"
			"\t\tfpAddress = GetProcAddress(hDll, pszProcName);\r\n"
			"\t\tif (fpAddress == NULL)\r\n"
				"\t\t{\r\n"
				"\t\t\t\tsprintf_s(szTemp, MAX_PATH, \"无法找到函数 :%s 的地址 \", pszProcName);\r\n"
				"\t\t\t\tMessageBoxA(NULL, szTemp, \"错误\", MB_OK);\r\n"
				"\t\t\t\tExitProcess(-2);\r\n"
			"\t\t}\r\n"
			"\t\t//返回真实地址\r\n"
			"\t\treturn fpAddress;\r\n"
		"}\r\n"
	"////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////\r\n\r\n\r\n"
	"////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////\r\n"
	"// DLL MAIN\r\n"
	"int WINAPI DllMain(HINSTANCE hInstance, DWORD fdwReason, PVOID pvReserved)\r\n"
	"{\r\n"
	"\t\tswitch (fdwReason)\r\n"
	"\t\t{\r\n"
	"\t\tcase DLL_PROCESS_ATTACH:\r\n"
	"\t\t\t\thDll = LoadLibraryA(\"%s\");\r\n"
	"\t\t\t\tif (!hDll)\r\n"
	"\t\t\t\t{\r\n"
	"\t\t\t\t\tOutputDebugStringA(\"获取真实模块失败\");\r\n"
	"\t\t\t\t\treturn FALSE;\r\n"
	"\t\t\t\t}\r\n"
	"\t\t\t\tOutputDebugStringA(\"附加成功\");\r\n"
	"\t\t\tbreak;\r\n"
	"\t\tcase DLL_PROCESS_DETACH:\r\n"
	"\t\t\t\tif (hDll != NULL)\r\n"
	"\t\t\t\t\tFreeLibrary(hDll); \r\n"
	"\t\t\tbreak; \r\n"
	"\t\t}\r\n"
	"\t\treturn TRUE;\r\n"

	"}\r\n"
	"////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////\r\n\r\n\r\n\r\n"
		,++dwIndex, "%s", szDllFileName);//szDllFileName
	dwWritten = 0;
	if (!WriteFile(hCFile, szTemp, strlen(szTemp), &dwWritten, NULL))
	{
		OutputDebugStringA("写入文件失败");
		UnmapViewOfFile(pMap);
		CloseHandle(hMap);
		CloseHandle(hFile);
		CloseHandle(hCFile);
		return FALSE;
	}
	dwWritten = 0;


	//写入函数部分
	pTemp = pLink;
	DWORD dwCount = 1;
	while (pTemp != NULL)
	{
		ZeroMemory(szTemp, 4096);
		sprintf_s(szTemp, 4096,
			"////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////\r\n"
			"//导出函数 %d  不要在里边定义变量\r\n"
			"ALCDECL %s%s()\r\n"
			"{\r\n"
			"//以下注释经过OD调试得出 编译环境:win10 x64 vs2013， \r\n"
			"\t\t//一般情况下在这里为所欲为   注意堆栈平衡\r\n"
			"\t\tGetAddress(\"%s\");\r\n"
			"\t\t//此时栈订保持的是返回地址,因为我们前面没有破坏堆栈\r\n"
			"\t\t__asm pop dwRetaddress[%d]						//弹出来，下面菜可以用call,为什么用call？因为如果用直接jmp的话 想获取执行返回值有点困难\r\n"
			"\t\t__asm call eax								//把返回地址入栈，这时候就相当于原来的返回地址被我们call的下一条指令地址入栈，这样真实函数返回后我们重新夺回控制权\r\n"
			"\t\t//一般情况下在这里继续为所欲为  注意堆栈平衡\r\n"
			"\t\t__asm jmp dword ptr dwRetaddress[%d]			//跳回原函数\r\n"
			"}\r\n"
			"////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////\r\n\r\n\r\n\r\n\r\n",
			dwCount,szMyHead, pTemp->szName, pTemp->szName,dwCount,dwCount
			);
		if (!WriteFile(hCFile, szTemp, strlen(szTemp), &dwWritten, NULL))
		{
			OutputDebugStringA("写入文件失败");
			UnmapViewOfFile(pMap);
			CloseHandle(hMap);
			CloseHandle(hFile);
			CloseHandle(hCFile);
			return FALSE;
		}
		pTemp = pTemp->next;
		dwCount++;
	}
	//收尾工作
	UnmapViewOfFile(pMap);
	CloseHandle(hMap);
	CloseHandle(hFile);
	CloseHandle(hCFile);
	return TRUE;
}


///////////////////////////////////////////////////////////////////////////////////////////////////
//功  能:初始化进程列标题
//参  数:列表控件的句柄
BOOL SetColumn_Process(HANDLE hProcessListContorl)
{
	
	PTCHAR pszListName[5] = { TEXT("序号"), TEXT("进程名称"), TEXT("PID"), TEXT("线程数"), TEXT("父进程ID") };
	for (int i = 0; i < 5; i++)
	{	
		OutputDebugString(pszListName[i]);
	}
	LVCOLUMN vcl;
	ListView_SetExtendedListViewStyle(hProcessListContorl, LVS_EX_FULLROWSELECT);  //需要这个扩展函数才可以选择行使其高亮    mother fuck！

	vcl.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM; //最后一个宏表示选择高亮
	for (int j = 0; j < 5; j++)
	{
		vcl.pszText = pszListName[j];//列标题
		vcl.cx = 100;//列宽
		vcl.iSubItem = j;//子项索引，第一列无子项
		ListView_InsertColumn(hProcessListContorl, j, &vcl);  //插入一项
	}
	return TRUE;
}
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//功  能:初始化进程列标题
//参  数:列表控件的句柄
//返回值:失败返回FALSE
BOOL ShowProcess(HANDLE hList_View)
{
	//清除所有列表内容
	ListView_DeleteAllItems(hList_View);
	/*获取进程快照*/
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);  //需要 头文件 TlHelp32.h
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		OutputDebugStringA("创建进程快照失败");
		return FALSE;
	}

	/*列举进程并添加到控件中*/
	PROCESSENTRY32 Pe32 = { 0 };
	//在使用这个结构前，先设置它的大小  
	Pe32.dwSize = sizeof(PROCESSENTRY32);
	//遍历进程快照，轮流显示每个进程的信息  
	BOOL bRet = Process32First(hSnapshot, &Pe32);
	LVITEM vitem;	 //列表的一项值
	vitem.mask = LVIF_TEXT;
	int i = 0; //序号
	int iList = 0;
	TCHAR sziIdex[10]; //序号
	for (;; i++)
	{
		//序号 从1开始
		wsprintfW(sziIdex, TEXT("%d"), i);
		vitem.pszText = sziIdex;
		vitem.iItem = i;          //对应行
		vitem.iSubItem = 0;      //对应列
		ListView_InsertItem(hList_View, &vitem); //第一次用insertitem，后再就在这个item（行）上 setitem的值，根据isubitem来确定是哪里列


		//名称
		vitem.pszText = Pe32.szExeFile;
		vitem.iSubItem = 1;
		ListView_SetItem(hList_View, &vitem);

		//PID
		ZeroMemory(sziIdex, sizeof(sziIdex));
		wsprintfW(sziIdex, TEXT("%d"), Pe32.th32ProcessID);
		vitem.pszText = sziIdex;
		vitem.iSubItem = 2;
		ListView_SetItem(hList_View, &vitem);
		//线程数
		ZeroMemory(sziIdex, sizeof(sziIdex));
		wsprintfW(sziIdex, TEXT("%d"), Pe32.cntThreads);
		vitem.pszText = sziIdex;
		vitem.iSubItem = 3;
		ListView_SetItem(hList_View, &vitem);
		//父进程ID
		ZeroMemory(sziIdex, sizeof(sziIdex));
		wsprintfW(sziIdex, TEXT("%d"), Pe32.th32ParentProcessID);
		vitem.pszText = sziIdex;
		vitem.iSubItem = 4;
		ListView_SetItem(hList_View, &vitem);
		//线程优先级
		ZeroMemory(sziIdex, sizeof(sziIdex));
		wsprintfW(sziIdex, TEXT("%d"), Pe32.pcPriClassBase);
		vitem.pszText = sziIdex;
		vitem.iSubItem = 5;
		ListView_SetItem(hList_View, &vitem);
		bRet = Process32Next(hSnapshot, &Pe32);
		if (!bRet)
			break;

	}


	CloseHandle(hSnapshot);
	return TRUE;
}
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//功  能:获取选中的进程ID
//参  数:选择的行
//返回值:pid
DWORD GetSelectProcessId(DWORD select)            
{
	TCHAR szPid[10] = { 0 };
	CHAR  szPidAscii[10] = { 0 };
	int ipid = -1;
	ListView_GetItemText(hProcessListContorl, select, 2, szPid, 10); //获取第三列的内容保存到szPid OK
	

	WideCharToMultiByte(CP_ACP, //The system default Windows ANSI code page
		0,
		szPid,
		_countof(szPid),
		szPidAscii,
		10,
		NULL,
		0);
	ipid = atoi(szPidAscii);  //此时获取到整形的pid
	return ipid;
}
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//功  能:初始化DLL列标题;
//参  数:列表控件句柄
BOOL SetColumn_Dll(HANDLE hDllListContorl)
{
	/*list_view控件列标题设置*/

	PTCHAR pszListName[3] = { TEXT("序号"), TEXT("名称"), TEXT("路径") };
	for (int i = 0; i < 3; i++)
	{
		OutputDebugString(pszListName[i]);
	}
	LVCOLUMN vcl;
	ListView_SetExtendedListViewStyle(hDllListContorl, LVS_EX_FULLROWSELECT);  //需要这个扩展函数才可以选择行使其高亮    mother fuck！

	vcl.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM; //最后一个宏表示选择高亮
	for (int j = 0; j < 2; j++)
	{
		vcl.pszText = pszListName[j];//列标题
		vcl.cx = 100 + j * 60;//列宽
		vcl.iSubItem = j;//子项索引，第一列无子项
		ListView_InsertColumn(hDllListContorl, j, &vcl);  //插入一项
	}
	vcl.pszText = pszListName[2];//列标题
	vcl.cx = 600;//列宽
	vcl.iSubItem = 2;//子项索引，第一列无子项
	ListView_InsertColumn(hDllListContorl, 2, &vcl);  //插入一项
	return TRUE;
}
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//功  能:显示可能被劫持的DLL
//参  数:1 列表控件句柄 2 目标dll
BOOL ShowDll(HANDLE hList_View, DWORD pid)      
{
	//获取knowndlls
	PSTSTRING pLink = GetKnowndllsNameList();
	PSTSTRING pTemp = pLink;
	//清除所有列表内容
	ListView_DeleteAllItems(hList_View);
	/*获取进程快照*/
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);   //需要 头文件 TlHelp32.h
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		OutputDebugStringA("创建进程dll快照失败");
		return FALSE;
	}

	/*列举进程dll并添加到控件中*/
	MODULEENTRY32 Me32 = { 0 };
	//在使用这个结构前，先设置它的大小  
	Me32.dwSize = sizeof(MODULEENTRY32);
	//遍历进程快照，轮流显示每个进程的信息  
	BOOL bRet = Module32First(hSnapshot, &Me32);
	LVITEM vitem;	    //列表的一项值
	vitem.mask = LVIF_TEXT;
	int i = 0;			//序号
	int iList = 0;
	TCHAR sziIdex[10];  //序号
	CHAR szTemp[MAX_PATH] = { 0 };
	BOOL bFlag = TRUE;
	//循环输出dll
	do{
		//过滤存在knowndlls中的dll
		ZeroMemory(szTemp, MAX_PATH);
		WideCharToMultiByte(CP_ACP, //The system default Windows ANSI code page
			0,
			Me32.szModule,
			_countof(Me32.szModule),
			szTemp,
			MAX_PATH,
			NULL,
			0);
		OutputDebugStringA(szTemp);
		//比较
		while (pTemp != NULL)
		{
			if (_stricmp(szTemp, pTemp->szName) == 0)
			{
				bFlag = FALSE;  //说明存在于knowndlls中
				break;			//存在着忽略 继续下一次循环

			}
			pTemp = pTemp->next;
		}
		if (bFlag != FALSE) //不再knowndlls中则输出到控件中
		{


			//序号 从1开始
			wsprintfW(sziIdex, TEXT("%d"), i);
			vitem.pszText = sziIdex;
			vitem.iItem = i;						 //对应行
			vitem.iSubItem = 0;						 //对应列
			ListView_InsertItem(hList_View, &vitem); //第一次用insertitem，后再就在这个item（行）上 setitem的值，根据isubitem来确定是哪里列


			//名称
			vitem.pszText = Me32.szModule;
			vitem.iSubItem = 1;
			ListView_SetItem(hList_View, &vitem);

			//路径
			vitem.pszText = Me32.szExePath;
			vitem.iSubItem = 2;
			ListView_SetItem(hList_View, &vitem);
			i++;
		}

		//存在则比较下一个dll是否存在于knowndlls中
		bFlag = TRUE;
		pTemp = pLink;
		
		
	} while (Module32Next(hSnapshot, &Me32));


	CloseHandle(hSnapshot);
	return TRUE;

}
///////////////////////////////////////////////////////////////////////////////////////////////////






///////////////////////////////////////////////////////////////////////////////////////////////////
//功  能:通过注册表 "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs" 获取knowndlls
//返回值:返回存储knodwndlls中所有dll字符串的链表
PSTSTRING GetKnowndllsNameList()
{
	DWORD dwValueSize = MAX_PATH;
	DWORD dwNameSize = MAX_PATH; ////必须赋值，否则会失败
	CHAR szValueName[MAX_PATH];
	CHAR szValue[MAX_PATH];
	DWORD dwType = REG_SZ;
	PSTSTRING pLink = NULL;  //用户返回的链表
	HKEY hKey = NULL;
	DWORD dwRet = 0;
	int dwIndex = 1;  //子键的索引

	//之前开始用的是RegOpenKeyA这个api 死活得不出结果
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		while (RegEnumValueA(hKey, dwIndex, szValueName, &dwNameSize, 0, &dwType, szValue, &dwValueSize) == ERROR_SUCCESS)
		{
			//printf_s("%s\n", szValue);

			 InsertName(&pLink, szValue);
			dwIndex++;
			dwValueSize = MAX_PATH;
			dwNameSize = MAX_PATH;  //必须赋值，否则会失败
		}
	}
	else
	{
		printf_s("打开注册表失败\n");
		return NULL;
	}

	RegCloseKey(hKey);
	return pLink;
}
///////////////////////////////////////////////////////////////////////////////////////////////////