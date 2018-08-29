/*
*	dll �ٳֹ���
*	2016-5-24
*	1.ֱ�������ٳֶ����ļ� 2.�����ܽٳֳɹ��Ķ���(��ȡ�����еĽ��̣��г���dll ѡ��ٳ�)
*/
#include "resource.h"
#include<windows.h>
#include<stdio.h>
#include <shlobj.h>    
#include<commctrl.h>
#include<TlHelp32.h>
#pragma comment(lib,"shell32.lib") //SHGetSpecialFolderPath�����õ�

///////////////////////////////////////////////////////////////////////////////////////////////////
//���ݽṹ
struct stString				//�洢dll���Ƶ����� Ϊʲô���ö�ά���飿ǿ��֢����
{
	CHAR szName[MAX_PATH];
	CHAR szPath[MAX_PATH];
	struct stString * next;
};
typedef struct stString STSTRING, *PSTSTRING;
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//���ڹ�������
INT_PTR CALLBACK MainDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK Sub1DlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK Sub2DlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

//����: ��س�ʼ�� ����MainDlgProc��ӷ��
void Init(HWND hdlg,UINT msg,WPARAM wParam,LPARAM lParam);

//����:��ȡĿ���ļ�ȫ·��
BOOL GetFilePath(PCHAR pszDllPath);	

//����:���ļ�����ȡdll�ļ�·�����༭����ʾ�ļ�ȫ·��
VOID Open();

//����:��ȡ����Ŀ���ļ�ȫ·��,�༭����ʾ������·��
VOID Save();

//����:��ȡ����Ŀ���ļ�ȫ·��
BOOL SaveFilePath(PCHAR pszCFilePath);

//����:�л������ģʽ
VOID HijactDll_DetectMode();

//����:����Ŀ�굼��������dll�ٳֵ�.c�ļ�
BOOL CreateDllSrc(PCSTR pszDllName,PCSTR pszSrcName);

//���ܣ����ַ�����������
BOOL InsertName(PSTSTRING *pLink, PCSTR pszName);	

//���ܳ�ʼ�������б���
BOOL SetColumn_Process(HANDLE hProcessListContorl);

//����:ö�ٽ��̵��б���
BOOL ShowProcess(HANDLE hList_View);

//����:��ȡѡ�еĽ���ID
DWORD GetSelectProcessId(DWORD select);

//��ʼ��DLL�б���;
BOOL SetColumn_Dll(HANDLE hDllListContorl); 

//�� ��:��ʾ���ܱ��ٳֵ�DLL
BOOL ShowDll(HANDLE hList_View, DWORD pid);

//����:ͨ��ע��� "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs" ��ȡknowndlls
PSTSTRING GetKnowndllsNameList();


///////////////////////////////////////////////////////////////////////////////////////////////////



///////////////////////////////////////////////////////////////////////////////////////////////////
//ȫ�ֱ���
CHAR szDllFileName[MAX_PATH];  //Ŀ��dllȫ·��
TCHAR wszDllFileName[MAX_PATH];  //Ŀ��dllȫ·��
CHAR szCFileName[MAX_PATH];    //�洢Ŀ��·��
HWND hdlg = NULL;			   //�Ի�����
HINSTANCE hint;				   //ʵ�����
HANDLE hProcessListContorl = NULL;				//��ʾ�����б����
HANDLE hDllListContorl = NULL;				    //��ʾDll�б����
HWND hdlg2 = NULL;								//��ʾ�����б��ڵĶԻ�����
DWORD dwProcessId = 0;							//����ID
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//������
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPreInstance, LPSTR lpCmdLine, int nCmdShow)
{
	hint = hInstance;
	//��������
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_MAIN), NULL, MainDlgProc);//���һ�����Ǵ��ڹ���,��Ϣѭ�����Լ����ˣ�����ֻҪ�Լ�д���ڹ���

}
///////////////////////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////////////////////
//���Ի������
INT_PTR CALLBACK MainDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	CHAR szTemp[MAX_PATH] = { 0 };
	DWORD dwRadioId = 0;
	hdlg = hDlg;											    		 //��ֵȫ�ֱ���������Ի�����
	switch (message)
	{

	case WM_INITDIALOG:
		//���ڳ�ʼ������
		Init(hDlg, message, wParam, lParam);
		break;
	case WM_COMMAND:
		//�ؼ���Ӧ LOWORD(wParam) ���ֵ�ǿؼ���ID
		switch (LOWORD(wParam))
		{
			//������ʽ
		case IDC_OPENDLL:
		case IDC_DETECTDLL:
			dwRadioId = LOWORD(wParam);									//����Radio ID
			if (dwRadioId == IDC_OPENDLL)								//˵��ѡ�д�DLL
				HijactDll_DetectMode(TRUE);
			else													    //˵��ѡ�����DLL
				HijactDll_DetectMode(FALSE);
			break;
			//���ļ�
		case IDC_1_3:
			Open();
			break;
			//�������·��
		case IDC_1_6:
			Save();
			break;
		case IDC_CREATE:
			if (!CreateDllSrc(szDllFileName, szCFileName))
				MessageBoxA(hDlg, "����Ŀ���ļ�ʧ��", "����", MB_OK);
			else
				MessageBoxA(hDlg, "����Ŀ���ļ��ɹ�", "��ϲ", MB_OK);
			break;
		case IDC_2_1:
			DialogBoxParamA(hint, MAKEINTRESOURCEA(IDD_2_PROCESSLIST), hDlg, Sub1DlgProc, (LPARAM)0); //dwInitParam��ָ�����ݵ��Ի�������е� WM_INITDIALOG ��Ϣ IParam ������ֵ��
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
//�����б�Ի������
INT_PTR CALLBACK Sub1DlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	hdlg2 = hDlg;
	DWORD dwSelect = -1; //���ѡ�е���
	switch (message)
	{


	case WM_INITDIALOG:
		//��ȡ�б�ؼ����
		hProcessListContorl = GetDlgItem(hDlg, IDC_PROCESSLIST); 
		 //��ʼ�������б���
		SetColumn_Process( hProcessListContorl);    
		//��ʾ���̵��б�ؼ�
		 ShowProcess(hProcessListContorl);
		break;
	case WM_COMMAND:

		//�ؼ���Ӧ LOWORD(wParam) ���ֵ�ǿؼ���ID
		switch (LOWORD(wParam))
		{
			//ȡ��
		case IDC_2_OUT:
			EndDialog(hDlg, 0);
			break;
			//�鿴DLL
		case IDC_2_BUTTON:
			//��ȡ����ID
			dwSelect = ListView_GetSelectionMark(hProcessListContorl);		//��ȡһ����ѡ�е��� ���浽iSelect �� OK
			if (dwSelect == -1)
			{
				MessageBoxA(hDlg, "��ѡ��һ������", "����", MB_OK);
				return FALSE;
			}
			//����
			ShowWindow(hDlg, FALSE);
			//�������� �������Ϊ����ID
			DialogBoxParamA(hint, MAKEINTRESOURCEA(IDD_2_DLL), hDlg, Sub2DlgProc, (LPARAM)GetSelectProcessId(dwSelect)); //dwInitParam��ָ�����ݵ��Ի�������е� WM_INITDIALOG ��Ϣ IParam ������ֵ��
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
//DLL�б�Ի������
INT_PTR CALLBACK Sub2DlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{

	DWORD dwSelect = -1; //���ѡ�е���
	switch (message)
	{


	case WM_INITDIALOG:
		//����Ĭ��·��
		SetDlgItemTextA(hDlg, IDC_2_SAVEPATH, szCFileName);
		dwProcessId = (DWORD)lParam;
		//��ȡ�б�ؼ����
		hDllListContorl = GetDlgItem(hDlg, IDC_DLLLIST);
		//��ʼ��DLL�б���
		SetColumn_Dll( hDllListContorl);     //��ʼ��DLL�б���;
		//��ʾ��knowndlls�е�dll���б�ؼ���
		ShowDll(hDllListContorl, dwProcessId);
		break;
	case WM_COMMAND:

		//�ؼ���Ӧ LOWORD(wParam) ���ֵ�ǿؼ���ID
		switch (LOWORD(wParam))
		{
		case IDC_2_CREATE:
			//��ȡѡ�е���
			dwSelect = ListView_GetSelectionMark(hDllListContorl);			//��ȡһ����ѡ�е��� ���浽dwSelect �� OK
			if (dwSelect == -1)
			{
				MessageBoxA(hDlg, "��ѡ��ģ��", "����", MB_OK);
				return FALSE;
			}
			ListView_GetItemText(hDllListContorl, dwSelect, 2, wszDllFileName, MAX_PATH); //��ȡ��2�е����ݱ��浽szDllFileName
			OutputDebugString(wszDllFileName);
			WideCharToMultiByte(CP_ACP, 0, wszDllFileName, _countof(wszDllFileName), szDllFileName, MAX_PATH, NULL, 0);
				
			if (!CreateDllSrc(szDllFileName, szCFileName))
				MessageBoxA(hDlg, "����Ŀ���ļ�ʧ��", "����", MB_OK);
			else
				MessageBoxA(hDlg, "����Ŀ���ļ��ɹ�", "��ϲ", MB_OK);
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
//����: ��س�ʼ�� ����MainDlgProc��ӷ��
void Init(HWND hdlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
	CheckRadioButton(hdlg, IDC_OPENDLL, IDC_DETECTDLL, IDC_OPENDLL); //��ʼ��ʱ��ѡ���һ��
	ShowWindow(GetDlgItem(hdlg, IDC_2_1), FALSE);					 //���ؿ�ʼ�ؼ�
	//��ʼ�������ļ�Ĭ��·��  Ϊ ����/FakeLib.c
	SHGetSpecialFolderPathA(NULL, szCFileName, CSIDL_DESKTOP, FALSE);
	strcat_s(szCFileName, MAX_PATH, "\\FakeLib.c");
	SetDlgItemTextA(hdlg, IDC_1_5, szCFileName);
}
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//��  ��:��ȡĿ���ļ�ȫ·��
//��  ��:����ȫ·���ļ��� 
//����ֵ:ʧ�ܷ���FALSE
BOOL GetFilePath(PCHAR pszDllPath)
{
	//����
	CHAR szFileFilter[] = "dll files(*.dll)\0*.dll\0\0"; //��һ���ַ����ǹ�������������ʾ�ַ��������磬���ı��ļ��������ڶ����ַ�ָ��������ʽ�����磬��*.TXT����
	OPENFILENAMEA ofn;
	//��ʼ��
	ZeroMemory(&ofn, sizeof(ofn));						//��ʼ�� Ϊ��
	ZeroMemory(pszDllPath, MAX_PATH);					//��ʼ�� Ϊ��
	//�ṹ���Ա����
	ofn.lStructSize = sizeof(ofn);						//�ṹ���СҪд
	ofn.hwndOwner = NULL;								//ָ�����ĸ����ڣ�ָ�����ĸ�����һ��ΪNULL����ʾ����ʹ�õ���ͨ�öԻ���
	ofn.lpstrFile = pszDllPath;							//���ڱ����ļ�������·�����ļ���
	ofn.lpstrFilter = szFileFilter;						//��������
	ofn.nMaxFile = MAX_PATH;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;  
	if (!GetOpenFileNameA(&ofn))
		return FALSE;
	//�ɹ�
	return TRUE;
}
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//����:���ļ�����ȡdll�ļ�·�����༭����ʾ�ļ�ȫ·��
VOID Open()
{
	if (!GetFilePath(szDllFileName))
		MessageBoxA(hdlg, "��ȡĿ���ļ�ʧ��", "����", MB_OK);
	else
		SetDlgItemTextA(hdlg, IDC_1_2, szDllFileName);
}
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//����:��ȡ����Ŀ���ļ�ȫ·��,�༭����ʾ������·��
VOID Save()
{
	if (!SaveFilePath(szCFileName))
		MessageBoxA(hdlg, "�����ļ���", "����", MB_OK);
	else
		SetDlgItemTextA(hdlg, IDC_1_5, szCFileName);
}
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//��  ��:����Ŀ���ļ�ȫ·��
//��  ��:���ܱ���·���ļ���
//����ֵ:ʧ�ܷ���FALSE
BOOL SaveFilePath(PCHAR pszCFilePath)
{
	CHAR szFileFilter[] = "dll files(*.c)\0*.c\0\0"; //��һ���ַ����ǹ�������������ʾ�ַ��������磬���ı��ļ��������ڶ����ַ�ָ��������ʽ�����磬��*.TXT����
	OPENFILENAMEA ofn;
	//��ʼ��
	ZeroMemory(&ofn, sizeof(ofn));					//��ʼ�� Ϊ��
	ZeroMemory(pszCFilePath, MAX_PATH);				//��ʼ�� Ϊ��
	//�ṹ���Ա����
	ofn.lStructSize = sizeof(ofn);					//�ṹ���СҪд
	ofn.hwndOwner = NULL;							//ָ�����ĸ����ڣ�ָ�����ĸ�����һ��ΪNULL����ʾ����ʹ�õ���ͨ�öԻ���
	ofn.lpstrFile = pszCFilePath;					// ���ڱ����ļ�������·�����ļ���
	ofn.lpstrFilter = szFileFilter;				    //��������
	ofn.nMaxFile = MAX_PATH;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST; 
	if (!GetSaveFileNameA(&ofn))
		return FALSE;
	//.c�ļ���׺
	strcat_s(pszCFilePath, MAX_PATH, ".c");
	return TRUE;
}
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//����:�л������ģʽ
//����:��TUREΪֱ�Ӵ�DLL�ļ�ģʽ��FALSEΪ���ģʽ
VOID HijactDll_DetectMode(BOOL bFalg)
{
	SetWindowTextA(GetDlgItem(hdlg, IDC_GROUP2), "����");
	//���ش򿪷�ʽ�����пؼ�
	for (int i = IDC_1_1; i <= IDC_1_6; i++)
		ShowWindow(GetDlgItem(hdlg, i), bFalg);
	ShowWindow(GetDlgItem(hdlg, IDC_CREATE), bFalg);
	//��ʾ��췽ʽ�����пؼ�
	ShowWindow(GetDlgItem(hdlg, IDC_2_1), !bFalg);
}
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//��  �ܣ����ַ�����������
//��  ����1.����ָ�� 2.Ҫ������ַ���
//����ֵ��ʧ�ܷ���FALSE,ʧ�ܵ�ԭ���������Ϊ�ڴ����ʧ��
BOOL InsertName(PSTSTRING *pLink, PCSTR pszName)
{
	PSTSTRING pTail = NULL;
	PSTSTRING pTemp = NULL;
	//�����µĽڵ�
	pTemp = (PSTSTRING)VirtualAlloc(NULL, sizeof(STSTRING), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pTemp == NULL)
	{
		OutputDebugStringA("��̬�����ڴ�ʧ��");
		return FALSE;
	}
	//��ʼ��������Ľڵ�
	ZeroMemory(pTemp->szName, MAX_PATH);
	pTemp->next = NULL;

	if (*pLink == NULL)			//��һ�β����ַ�������
	{

		*pLink = pTemp;
		strcpy_s(pTemp->szName, MAX_PATH, pszName);

	}
	else
	{

		//���ǵ�һ��
		pTail = *pLink;
		while (pTail->next != NULL) //�ƶ������һ���ڵ�
			pTail = pTail->next;
		pTail->next = pTemp;
		strcpy_s(pTemp->szName, MAX_PATH, pszName);
	}
	return TRUE;
}
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//��  ��:����Ŀ��pe����������dll�ٳֵ�.c�ļ�
//��  ��:1,Ŀ���ļ�·�� 2.���ɵ�cԴ�����ļ�·��
//����ֵ: ʧ�ܷ���FALSE
BOOL CreateDllSrc(PCSTR pszDllName, PCSTR pszSrcName)
{
	HANDLE hFile = NULL;	

	//��һ�� ���ļ�
	hFile = CreateFileA(pszDllName, GENERIC_READ, 0, NULL, OPEN_EXISTING, (DWORD)NULL, (HANDLE)NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		OutputDebugStringA("��DLL�ļ�ʧ�ܣ�\n");
		return FALSE;
	}
	
	//�ڶ��� �����ļ�ӳ��
	HANDLE hMap = NULL;
	hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, 0);   //ע�����SEC_IMAGE��ʽ��ѡ�������֮�����ǲ�����FOA �� RVA��ת����
	if (!hMap)
	{
		OutputDebugStringA("�����ļ�ӳ��ʧ��");;
		CloseHandle(hFile);
		return FALSE;
	}

	//������ ӳ�䵽�Լ����̵Ŀռ�
	LPVOID pMap = NULL;
	pMap = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);    //��ʱ��pMap ����DOSͷ��
	if (!pMap)
	{
		OutputDebugStringA("ӳ�䵽����ʧ��");
		CloseHandle(hMap);
		CloseHandle(hFile);
		return FALSE;
	}

	//���Ĳ� ����PE�ṹ�����������д���CԴ���ļ�����
	PIMAGE_DOS_HEADER pDosHeader = NULL;				 //DOS ͷָ��
	PIMAGE_NT_HEADERS pPeHeader = NULL;					 //PE  ͷָ��
	pDosHeader = (PIMAGE_DOS_HEADER)pMap;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)      //�ж��Ƿ�PE�ļ�������ֻ�ж�DOSͷ
	{
		OutputDebugStringA("����PE�ļ�");
		UnmapViewOfFile(pMap);
		CloseHandle(hMap);
		CloseHandle(hFile);
		return FALSE;
	}

	
	pPeHeader = (PIMAGE_NT_HEADERS)((DWORD)pMap + pDosHeader->e_lfanew);			//���PEͷ�ļ�ָ��
	//��ȡ������VA��ַ
	PIMAGE_EXPORT_DIRECTORY  pExportDirectory;									    
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pMap + pPeHeader->OptionalHeader.DataDirectory[0].VirtualAddress);		

	//����������
	//����ȫ��������ʽ��ѭ��Ҳֻ��һ��ѡ��
	DWORD FunctionNameRVA = 0;
	PDWORD pFunctionName = NULL;
	int iIndexAddressOfNameOrdinals = 0;

	//��������ͷ
	PSTSTRING pLink = NULL;

	//ָ����ͷ�ۣ���Ҫע�����AddressOfNameOrdinalsָ�����һ��WORD���飬����DWORD����!!!
	//���о�������ת���Լ�ָ����������Ϳ������
	for (DWORD i = 0; i < (pExportDirectory->NumberOfFunctions); i++)
	{

		iIndexAddressOfNameOrdinals = *((WORD*)((DWORD)pExportDirectory->AddressOfNameOrdinals + (DWORD)pDosHeader) + i); //���ţ�Ҫ��������ȡ������ַ
		FunctionNameRVA = *((DWORD*)((DWORD)pExportDirectory->AddressOfNames + (DWORD)pDosHeader + i * 4));
		//��ʱ��pFunctionNameָ�򵼳���������
		pFunctionName = (PDWORD)(FunctionNameRVA + (DWORD)pDosHeader); 

		//�Ѻ������뵽������
		if (!InsertName(&pLink, (PCSTR)pFunctionName))
		{
			UnmapViewOfFile(pMap);
			CloseHandle(hMap);
			CloseHandle(hFile);
			return FALSE;
		}

	}
			
	////���� ������� ����������ȡok
	//PSTSTRING ptemp = pLink;
	//while (ptemp != NULL)
	//{
	//	OutputDebugStringA(ptemp->szName);
	//	ptemp = ptemp->next;
	//}
	
	//����Ŀ���ļ�
	HANDLE hCFile = NULL;
	hCFile = CreateFileA(pszSrcName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hCFile == INVALID_HANDLE_VALUE)
	{
		OutputDebugStringA("����Ŀ���ļ�ʧ��");
		UnmapViewOfFile(pMap);
		CloseHandle(hMap);
		CloseHandle(hFile);
		return FALSE;
	}



	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//��ʼд���ļ�
	CHAR szMyHead[20] = "JMP_";
	DWORD dwWritten = 0;
	CHAR szTemp[4096] = { 0 };
	sprintf_s(szTemp, sizeof(szTemp),

		"#include<windows.h>\r\n"
		"#include<stdio.h>\r\n\r\n\r\n"
		"////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////\r\n"
		"// ��������\r\n"
		);
	//д��̶�����
	if (!WriteFile(hCFile, szTemp, strlen(szTemp), &dwWritten, NULL))
	{
		OutputDebugStringA("д���ļ�ʧ��");
		UnmapViewOfFile(pMap);
		CloseHandle(hMap);
		CloseHandle(hFile);
		CloseHandle(hCFile);
		return FALSE;
	}
	dwWritten = 0;

	//д��#pragma comment����
	PSTSTRING pTemp = pLink;
	DWORD dwIndex = 1;
	while (pTemp != NULL)
	{
		ZeroMemory(szTemp, 4096);
		sprintf_s(szTemp, sizeof(szTemp), "#pragma comment(linker, \"/EXPORT:%s=_%s%s,@%d\")\r\n", pTemp->szName, szMyHead,pTemp->szName, dwIndex);
		pTemp = pTemp->next;
		dwIndex++;
		//д��
		if (!WriteFile(hCFile, szTemp, strlen(szTemp), &dwWritten, NULL))
		{
			OutputDebugStringA("д���ļ�ʧ��");
			UnmapViewOfFile(pMap);
			CloseHandle(hMap);
			CloseHandle(hFile);
			CloseHandle(hCFile);
			return FALSE;
		}
		dwWritten = 0;
	}
	
	dwIndex--;

	
	//д��̶�����
	dwWritten = 0;
	ZeroMemory(szTemp, sizeof(szTemp));
	sprintf_s(szTemp,sizeof(szTemp), 
		"////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////\r\n\r\n\r\n\r\n\r\n"
		"////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////\r\n"
		"// �궨��\r\n"
		"#define EXTERNC extern \"C\"\n"
		"#define NAKED __declspec(naked)\n"
		"#define EXPORT __declspec(dllexport)\n"

		"#define ALCPP EXPORT NAKED\n"
		"#define ALSTD EXTERNC EXPORT NAKED void __stdcall\n"
		"#define ALCFAST EXTERNC EXPORT NAKED void __fastcall\n"
		"#define ALCDECL EXTERNC NAKED void __cdecl\n"
		"////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////\r\n\r\n\r\n\r\n\r\n"
		"////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////\r\n"
		"//ȫ�ֱ���\r\n"
		"HMODULE hDll = NULL;\r\n"
		"DWORD dwRetaddress[%d];							//��ŷ��ص�ַ\r\n"
		"////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////\r\n\r\n\r\n\r\n\r\n"
		"////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////\r\n"
		"// �ڲ����� ��ȡ��ʵ������ַ\r\n"
		"FARPROC WINAPI GetAddress(PCSTR pszProcName)\r\n"
		"{\r\n"
			"\t\tFARPROC fpAddress;\r\n"
			"\t\tCHAR szTemp[MAX_PATH] = { 0 };\r\n"
			"\t\tfpAddress = GetProcAddress(hDll, pszProcName);\r\n"
			"\t\tif (fpAddress == NULL)\r\n"
				"\t\t{\r\n"
				"\t\t\t\tsprintf_s(szTemp, MAX_PATH, \"�޷��ҵ����� :%s �ĵ�ַ \", pszProcName);\r\n"
				"\t\t\t\tMessageBoxA(NULL, szTemp, \"����\", MB_OK);\r\n"
				"\t\t\t\tExitProcess(-2);\r\n"
			"\t\t}\r\n"
			"\t\t//������ʵ��ַ\r\n"
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
	"\t\t\t\t\tOutputDebugStringA(\"��ȡ��ʵģ��ʧ��\");\r\n"
	"\t\t\t\t\treturn FALSE;\r\n"
	"\t\t\t\t}\r\n"
	"\t\t\t\tOutputDebugStringA(\"���ӳɹ�\");\r\n"
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
		OutputDebugStringA("д���ļ�ʧ��");
		UnmapViewOfFile(pMap);
		CloseHandle(hMap);
		CloseHandle(hFile);
		CloseHandle(hCFile);
		return FALSE;
	}
	dwWritten = 0;


	//д�뺯������
	pTemp = pLink;
	DWORD dwCount = 1;
	while (pTemp != NULL)
	{
		ZeroMemory(szTemp, 4096);
		sprintf_s(szTemp, 4096,
			"////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////\r\n"
			"//�������� %d  ��Ҫ����߶������\r\n"
			"ALCDECL %s%s()\r\n"
			"{\r\n"
			"//����ע�;���OD���Եó� ���뻷��:win10 x64 vs2013�� \r\n"
			"\t\t//һ�������������Ϊ����Ϊ   ע���ջƽ��\r\n"
			"\t\tGetAddress(\"%s\");\r\n"
			"\t\t//��ʱջ�����ֵ��Ƿ��ص�ַ,��Ϊ����ǰ��û���ƻ���ջ\r\n"
			"\t\t__asm pop dwRetaddress[%d]						//������������˿�����call,Ϊʲô��call����Ϊ�����ֱ��jmp�Ļ� ���ȡִ�з���ֵ�е�����\r\n"
			"\t\t__asm call eax								//�ѷ��ص�ַ��ջ����ʱ����൱��ԭ���ķ��ص�ַ������call����һ��ָ���ַ��ջ��������ʵ�������غ��������¶�ؿ���Ȩ\r\n"
			"\t\t//һ����������������Ϊ����Ϊ  ע���ջƽ��\r\n"
			"\t\t__asm jmp dword ptr dwRetaddress[%d]			//����ԭ����\r\n"
			"}\r\n"
			"////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////\r\n\r\n\r\n\r\n\r\n",
			dwCount,szMyHead, pTemp->szName, pTemp->szName,dwCount,dwCount
			);
		if (!WriteFile(hCFile, szTemp, strlen(szTemp), &dwWritten, NULL))
		{
			OutputDebugStringA("д���ļ�ʧ��");
			UnmapViewOfFile(pMap);
			CloseHandle(hMap);
			CloseHandle(hFile);
			CloseHandle(hCFile);
			return FALSE;
		}
		pTemp = pTemp->next;
		dwCount++;
	}
	//��β����
	UnmapViewOfFile(pMap);
	CloseHandle(hMap);
	CloseHandle(hFile);
	CloseHandle(hCFile);
	return TRUE;
}


///////////////////////////////////////////////////////////////////////////////////////////////////
//��  ��:��ʼ�������б���
//��  ��:�б�ؼ��ľ��
BOOL SetColumn_Process(HANDLE hProcessListContorl)
{
	
	PTCHAR pszListName[5] = { TEXT("���"), TEXT("��������"), TEXT("PID"), TEXT("�߳���"), TEXT("������ID") };
	for (int i = 0; i < 5; i++)
	{	
		OutputDebugString(pszListName[i]);
	}
	LVCOLUMN vcl;
	ListView_SetExtendedListViewStyle(hProcessListContorl, LVS_EX_FULLROWSELECT);  //��Ҫ�����չ�����ſ���ѡ����ʹ�����    mother fuck��

	vcl.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM; //���һ�����ʾѡ�����
	for (int j = 0; j < 5; j++)
	{
		vcl.pszText = pszListName[j];//�б���
		vcl.cx = 100;//�п�
		vcl.iSubItem = j;//������������һ��������
		ListView_InsertColumn(hProcessListContorl, j, &vcl);  //����һ��
	}
	return TRUE;
}
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//��  ��:��ʼ�������б���
//��  ��:�б�ؼ��ľ��
//����ֵ:ʧ�ܷ���FALSE
BOOL ShowProcess(HANDLE hList_View)
{
	//��������б�����
	ListView_DeleteAllItems(hList_View);
	/*��ȡ���̿���*/
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);  //��Ҫ ͷ�ļ� TlHelp32.h
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		OutputDebugStringA("�������̿���ʧ��");
		return FALSE;
	}

	/*�оٽ��̲���ӵ��ؼ���*/
	PROCESSENTRY32 Pe32 = { 0 };
	//��ʹ������ṹǰ�����������Ĵ�С  
	Pe32.dwSize = sizeof(PROCESSENTRY32);
	//�������̿��գ�������ʾÿ�����̵���Ϣ  
	BOOL bRet = Process32First(hSnapshot, &Pe32);
	LVITEM vitem;	 //�б��һ��ֵ
	vitem.mask = LVIF_TEXT;
	int i = 0; //���
	int iList = 0;
	TCHAR sziIdex[10]; //���
	for (;; i++)
	{
		//��� ��1��ʼ
		wsprintfW(sziIdex, TEXT("%d"), i);
		vitem.pszText = sziIdex;
		vitem.iItem = i;          //��Ӧ��
		vitem.iSubItem = 0;      //��Ӧ��
		ListView_InsertItem(hList_View, &vitem); //��һ����insertitem�����پ������item���У��� setitem��ֵ������isubitem��ȷ����������


		//����
		vitem.pszText = Pe32.szExeFile;
		vitem.iSubItem = 1;
		ListView_SetItem(hList_View, &vitem);

		//PID
		ZeroMemory(sziIdex, sizeof(sziIdex));
		wsprintfW(sziIdex, TEXT("%d"), Pe32.th32ProcessID);
		vitem.pszText = sziIdex;
		vitem.iSubItem = 2;
		ListView_SetItem(hList_View, &vitem);
		//�߳���
		ZeroMemory(sziIdex, sizeof(sziIdex));
		wsprintfW(sziIdex, TEXT("%d"), Pe32.cntThreads);
		vitem.pszText = sziIdex;
		vitem.iSubItem = 3;
		ListView_SetItem(hList_View, &vitem);
		//������ID
		ZeroMemory(sziIdex, sizeof(sziIdex));
		wsprintfW(sziIdex, TEXT("%d"), Pe32.th32ParentProcessID);
		vitem.pszText = sziIdex;
		vitem.iSubItem = 4;
		ListView_SetItem(hList_View, &vitem);
		//�߳����ȼ�
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
//��  ��:��ȡѡ�еĽ���ID
//��  ��:ѡ�����
//����ֵ:pid
DWORD GetSelectProcessId(DWORD select)            
{
	TCHAR szPid[10] = { 0 };
	CHAR  szPidAscii[10] = { 0 };
	int ipid = -1;
	ListView_GetItemText(hProcessListContorl, select, 2, szPid, 10); //��ȡ�����е����ݱ��浽szPid OK
	

	WideCharToMultiByte(CP_ACP, //The system default Windows ANSI code page
		0,
		szPid,
		_countof(szPid),
		szPidAscii,
		10,
		NULL,
		0);
	ipid = atoi(szPidAscii);  //��ʱ��ȡ�����ε�pid
	return ipid;
}
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//��  ��:��ʼ��DLL�б���;
//��  ��:�б�ؼ����
BOOL SetColumn_Dll(HANDLE hDllListContorl)
{
	/*list_view�ؼ��б�������*/

	PTCHAR pszListName[3] = { TEXT("���"), TEXT("����"), TEXT("·��") };
	for (int i = 0; i < 3; i++)
	{
		OutputDebugString(pszListName[i]);
	}
	LVCOLUMN vcl;
	ListView_SetExtendedListViewStyle(hDllListContorl, LVS_EX_FULLROWSELECT);  //��Ҫ�����չ�����ſ���ѡ����ʹ�����    mother fuck��

	vcl.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM; //���һ�����ʾѡ�����
	for (int j = 0; j < 2; j++)
	{
		vcl.pszText = pszListName[j];//�б���
		vcl.cx = 100 + j * 60;//�п�
		vcl.iSubItem = j;//������������һ��������
		ListView_InsertColumn(hDllListContorl, j, &vcl);  //����һ��
	}
	vcl.pszText = pszListName[2];//�б���
	vcl.cx = 600;//�п�
	vcl.iSubItem = 2;//������������һ��������
	ListView_InsertColumn(hDllListContorl, 2, &vcl);  //����һ��
	return TRUE;
}
///////////////////////////////////////////////////////////////////////////////////////////////////





///////////////////////////////////////////////////////////////////////////////////////////////////
//��  ��:��ʾ���ܱ��ٳֵ�DLL
//��  ��:1 �б�ؼ���� 2 Ŀ��dll
BOOL ShowDll(HANDLE hList_View, DWORD pid)      
{
	//��ȡknowndlls
	PSTSTRING pLink = GetKnowndllsNameList();
	PSTSTRING pTemp = pLink;
	//��������б�����
	ListView_DeleteAllItems(hList_View);
	/*��ȡ���̿���*/
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);   //��Ҫ ͷ�ļ� TlHelp32.h
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		OutputDebugStringA("��������dll����ʧ��");
		return FALSE;
	}

	/*�оٽ���dll����ӵ��ؼ���*/
	MODULEENTRY32 Me32 = { 0 };
	//��ʹ������ṹǰ�����������Ĵ�С  
	Me32.dwSize = sizeof(MODULEENTRY32);
	//�������̿��գ�������ʾÿ�����̵���Ϣ  
	BOOL bRet = Module32First(hSnapshot, &Me32);
	LVITEM vitem;	    //�б��һ��ֵ
	vitem.mask = LVIF_TEXT;
	int i = 0;			//���
	int iList = 0;
	TCHAR sziIdex[10];  //���
	CHAR szTemp[MAX_PATH] = { 0 };
	BOOL bFlag = TRUE;
	//ѭ�����dll
	do{
		//���˴���knowndlls�е�dll
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
		//�Ƚ�
		while (pTemp != NULL)
		{
			if (_stricmp(szTemp, pTemp->szName) == 0)
			{
				bFlag = FALSE;  //˵��������knowndlls��
				break;			//�����ź��� ������һ��ѭ��

			}
			pTemp = pTemp->next;
		}
		if (bFlag != FALSE) //����knowndlls����������ؼ���
		{


			//��� ��1��ʼ
			wsprintfW(sziIdex, TEXT("%d"), i);
			vitem.pszText = sziIdex;
			vitem.iItem = i;						 //��Ӧ��
			vitem.iSubItem = 0;						 //��Ӧ��
			ListView_InsertItem(hList_View, &vitem); //��һ����insertitem�����پ������item���У��� setitem��ֵ������isubitem��ȷ����������


			//����
			vitem.pszText = Me32.szModule;
			vitem.iSubItem = 1;
			ListView_SetItem(hList_View, &vitem);

			//·��
			vitem.pszText = Me32.szExePath;
			vitem.iSubItem = 2;
			ListView_SetItem(hList_View, &vitem);
			i++;
		}

		//������Ƚ���һ��dll�Ƿ������knowndlls��
		bFlag = TRUE;
		pTemp = pLink;
		
		
	} while (Module32Next(hSnapshot, &Me32));


	CloseHandle(hSnapshot);
	return TRUE;

}
///////////////////////////////////////////////////////////////////////////////////////////////////






///////////////////////////////////////////////////////////////////////////////////////////////////
//��  ��:ͨ��ע��� "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs" ��ȡknowndlls
//����ֵ:���ش洢knodwndlls������dll�ַ���������
PSTSTRING GetKnowndllsNameList()
{
	DWORD dwValueSize = MAX_PATH;
	DWORD dwNameSize = MAX_PATH; ////���븳ֵ�������ʧ��
	CHAR szValueName[MAX_PATH];
	CHAR szValue[MAX_PATH];
	DWORD dwType = REG_SZ;
	PSTSTRING pLink = NULL;  //�û����ص�����
	HKEY hKey = NULL;
	DWORD dwRet = 0;
	int dwIndex = 1;  //�Ӽ�������

	//֮ǰ��ʼ�õ���RegOpenKeyA���api ����ò������
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		while (RegEnumValueA(hKey, dwIndex, szValueName, &dwNameSize, 0, &dwType, szValue, &dwValueSize) == ERROR_SUCCESS)
		{
			//printf_s("%s\n", szValue);

			 InsertName(&pLink, szValue);
			dwIndex++;
			dwValueSize = MAX_PATH;
			dwNameSize = MAX_PATH;  //���븳ֵ�������ʧ��
		}
	}
	else
	{
		printf_s("��ע���ʧ��\n");
		return NULL;
	}

	RegCloseKey(hKey);
	return pLink;
}
///////////////////////////////////////////////////////////////////////////////////////////////////