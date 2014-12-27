
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
    ULONG            ProcessId;             // 进程ID 
    UCHAR            ObjectName[MAX_PATH];  // 名字
    UCHAR            ObjType[128];          // 类型
    ACCESS_MASK      GrantedAccess;         // 对象权限
    // 远端进程空间地址，不允许进行访问, 所以这里也不需要进行关闭
    HANDLE           Handle;             
    PVOID            Object;

    // 释放是全局行为
    bool ReleaseMutant()
    {
        BOOL bRelease = FALSE;
        // 现在这里开启一个远程线程，让远端进程主动调用 CloseHandle
        const int RemoteThreadSize =  1024;
        const int RemoteParamSize = sizeof(Handle);

        // 获取需要注入的函数
        HMODULE hDllMoudle = NULL;
        hDllMoudle = LoadLibrary( "Kernel32.dll" );
        m_CloseHandle = (CloseHandleFunc)GetProcAddress( hDllMoudle, "CloseHandle" );
        if ( !m_CloseHandle ) return false;

        // 开启远程线程
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
            //等待远程线程结束
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
        // 只用到这个 16 号。就不写其他了。
        SystemLockInformation   = 12,
        SystemHandleInformation = 16,
        SystemObjectInformation = 17
    } SYSTEM_INFORMATION_CLASS;

    typedef enum _OBJECT_INFORMATION_CLASS 
    {
        // 只用到这个 1 号。就不写其他了。
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

    // 对应 16 号的一个数据结构
    typedef struct _SYSTEM_HANDLE_INFORMATION
    {
        ULONG            ProcessId;
        UCHAR            ObjectTypeNumber;
        UCHAR            Flags;
        USHORT           Handle;
        PVOID            Object;
        ACCESS_MASK      GrantedAccess;
    } SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

    // 对应 17 号的一个数据结构
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

    // 对应 1 号的一个数据结构
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
    // 指向函数的指针
    ZWQUERYSYSTEMINFORMATION m_pZWQuerySystemInfoformation;
    ZWQUERYOBJECT            m_pZWQueryObject;
    ZwDuplicateObject        m_pZwDuplicateObject;
    ZwClose                  m_pZwClose;
    const std::string        m_NtDllName;
};

