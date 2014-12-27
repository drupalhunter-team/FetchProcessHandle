
#include <windows.h>
#include <assert.h>
#include <aclapi.h>
#include <conio.h>
#include <functional>
#include <algorithm>    // std::find


struct FetchProcessHandleResult
{
private:
    typedef BOOL ( __stdcall *CloseHandleFunc )( HANDLE hObject );
    CloseHandleFunc m_CloseHandle;
public:
    ULONG            ProcessId;             // ����ID 
    UCHAR            ObjectName[MAX_PATH];  // ����
    UCHAR            ObjType[128];          // ����
    ACCESS_MASK      GrantedAccess;         // ����Ȩ��
    // Զ�˽��̿ռ��ַ����������з���, ��������Ҳ����Ҫ���йر�
    HANDLE           Handle;             
    PVOID            Object;

    // �ͷ���ȫ����Ϊ
    bool ReleaseMutant()
    {
        BOOL bRelease = FALSE;
        // �������￪��һ��Զ���̣߳���Զ�˽����������� CloseHandle
        const int RemoteThreadSize =  1024;
        const int RemoteParamSize = sizeof(Handle);

        // ��ȡ��Ҫע��ĺ���
        HMODULE hDllMoudle = NULL;
        hDllMoudle = LoadLibrary( "Kernel32.dll" );
        m_CloseHandle = (CloseHandleFunc)GetProcAddress( hDllMoudle, "CloseHandle" );
        if ( !m_CloseHandle ) return false;

        // ����Զ���߳�
        HANDLE hRemoteProcess = OpenProcess( PROCESS_ALL_ACCESS , FALSE, ProcessId );     
        if ( !hRemoteProcess ) return false;

        PVOID pRemoteThread = VirtualAllocEx( hRemoteProcess, NULL, RemoteThreadSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE ); 
        if ( !pRemoteThread )
        { 
            CloseHandle(hRemoteProcess); 
            FreeLibrary( hDllMoudle );
            return false; 
        }

        if ( WriteProcessMemory(hRemoteProcess, pRemoteThread, m_CloseHandle, RemoteThreadSize, 0)==FALSE )
        {
            VirtualFreeEx( hRemoteProcess, pRemoteThread, 0, MEM_RELEASE );
            CloseHandle  ( hRemoteProcess );
            FreeLibrary( hDllMoudle );
            return false;
        }

        HANDLE hRemoteThread = CreateRemoteThread( hRemoteProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteThread, Handle, 0, 0 );
        if ( hRemoteThread )
        {
            //�ȴ�Զ���߳̽���
            WaitForSingleObject( hRemoteThread, INFINITE );
            bRelease = true;
        }
        else
            assert( false );

        VirtualFreeEx ( hRemoteProcess, pRemoteThread, 0, MEM_RELEASE );
        CloseHandle   ( hRemoteProcess );
        FreeLibrary   ( hDllMoudle );
        return !!bRelease;
    }
};

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_ACCESS_DENIED        ((NTSTATUS)0xC0000022L)

class FetchProcessHandle 
{
private:
    typedef enum _SYSTEM_INFORMATION_CLASS
    {
        // ֻ�õ���� 16 �š��Ͳ�д�����ˡ�
        SystemLockInformation   = 12,
        SystemHandleInformation = 16,
        SystemObjectInformation = 17
    } SYSTEM_INFORMATION_CLASS;

    typedef enum _OBJECT_INFORMATION_CLASS 
    {
        // ֻ�õ���� 1 �š��Ͳ�д�����ˡ�
        ObjectNameInformation = 1,    
        ObjectTypeInformation = 2
    } OBJECT_INFORMATION_CLASS;

    typedef NTSTATUS ( __stdcall *ZWQUERYSYSTEMINFORMATION ) 
        ( IN FetchProcessHandle::SYSTEM_INFORMATION_CLASS SystemInformationClass, IN OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL );

    typedef NTSTATUS ( __stdcall *ZWQUERYOBJECT )
        ( IN HANDLE ObjectHandle, IN OBJECT_INFORMATION_CLASS ObjectInformationClass, OUT PVOID ObjectInformation, IN ULONG ObjectInformationLength, OUT PULONG ReturnLength OPTIONAL );

    typedef NTSTATUS ( __stdcall *ZwDuplicateObject )
        ( IN HANDLE SourceProcessHandle, IN HANDLE SourceHandle, IN HANDLE TargetProcessHandle, OUT PHANDLE TargetHandle OPTIONAL, IN ACCESS_MASK DesiredAccess, IN ULONG Attributes, IN ULONG Options );

    typedef NTSTATUS ( __stdcall *ZwClose )( IN HANDLE Handle );

    typedef LONG     NTSTATUS;
    typedef ULONG    ACCESS_MASK;

    typedef struct
    {
        USHORT Length;
        USHORT MaxLen;
        USHORT *Buffer;
    }UNICODE_STRING, *PUNICODE_STRING;

    // ��Ӧ 16 �ŵ�һ�����ݽṹ
    typedef struct _SYSTEM_HANDLE_INFORMATION
    {
        ULONG            ProcessId;
        UCHAR            ObjectTypeNumber;
        UCHAR            Flags;
        USHORT           Handle;
        PVOID            Object;
        ACCESS_MASK      GrantedAccess;
    } SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

    // ��Ӧ 17 �ŵ�һ�����ݽṹ
    typedef struct _SYSTEM_OBJECT_INFORMATION 
    {
        ULONG NextEntryOffset;
        PVOID Object;
        ULONG CreatorProcessId;
        USHORT Unknown;
        USHORT Flags;
        ULONG PointerCount;
        ULONG HandleCount;
        ULONG PagedPoolUsage;
        ULONG NonPagedPoolUsage;
        ULONG ExclusiveProcessId;
        PSECURITY_DESCRIPTOR SecurityDescriptor;
        UNICODE_STRING Name;
    } SYSTEM_OBJECT_INFORMATION, *PSYSTEM_OBJECT_INFORMATION;

    // ��Ӧ 1 �ŵ�һ�����ݽṹ
    typedef struct _OBJECT_NAME_INFORMATION 
    { 
        // Information Class 1
        UNICODE_STRING Name;
    } OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

public:
    FetchProcessHandle( const int Pid, std::function<bool(FetchProcessHandleResult&)> cbFetchResult );
    ~FetchProcessHandle();
private:
    bool AdjustProcessTokenPrivilege();
    void LoadNtDll();
    void Query( const int Pid, std::function<bool(FetchProcessHandleResult&)> cbFetchResult );

    void OnQuerySucess( const int Pid, ULONG NumberOfHandle, SYSTEM_HANDLE_INFORMATION* pResult, std::function<bool(FetchProcessHandleResult&)> cbFetchResult );
    inline BOOL NT_SUCCESS( NTSTATUS NtStatus ){ return NtStatus>=0; }
private:
    // ָ������ָ��
    ZWQUERYSYSTEMINFORMATION m_pZWQuerySystemInfoformation;
    ZWQUERYOBJECT            m_pZWQueryObject;
    ZwDuplicateObject        m_pZwDuplicateObject;
    ZwClose                  m_pZwClose;
    const std::string        m_NtDllName;
};

