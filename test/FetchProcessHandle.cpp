#include "FetchProcessHandle.h"


FetchProcessHandle::FetchProcessHandle( const int Pid, std::function<bool(FetchProcessHandleResult&)> cbFetchResult )
    : m_pZWQuerySystemInfoformation ( nullptr ),
      m_pZWQueryObject( nullptr ),
      m_NtDllName( "ntdll.dll" )
{
    AdjustProcessTokenPrivilege();
    LoadNtDll();
    Query( Pid, cbFetchResult );
}

FetchProcessHandle::~FetchProcessHandle()
{
    m_pZWQuerySystemInfoformation = nullptr;
    m_pZWQueryObject              = nullptr;
}

bool FetchProcessHandle::AdjustProcessTokenPrivilege()
{
    LUID             luidTmp;
    HANDLE           hToken;
    TOKEN_PRIVILEGES tkp;

    if ( !OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken) )
    {
        assert( false );
        return false;
    }

    if ( !LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidTmp) )
    {
        assert( false );
        CloseHandle( hToken );
        return false;
    }

    tkp.PrivilegeCount           = 1;
    tkp.Privileges[0].Luid       = luidTmp;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if ( !AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL) )
    {
        assert( false );
        CloseHandle(hToken);
        return false;
    }
    return true;
}

void FetchProcessHandle::LoadNtDll()
{
    HMODULE hDllModule = NULL;
    hDllModule         = GetModuleHandleA( m_NtDllName.c_str() );
    if ( hDllModule == NULL ) return ;
    m_pZWQuerySystemInfoformation = ( ZWQUERYSYSTEMINFORMATION )GetProcAddress( hDllModule, "ZwQuerySystemInformation" );
    m_pZWQueryObject              = ( ZWQUERYOBJECT )GetProcAddress( hDllModule, "ZwQueryObject" );
    m_pZwDuplicateObject          = ( ZwDuplicateObject )GetProcAddress( hDllModule, "ZwDuplicateObject" );
    m_pZwClose                    = ( ZwClose )GetProcAddress( hDllModule, "ZwClose" );
    assert( m_pZWQuerySystemInfoformation&&m_pZWQueryObject );
    FreeLibrary( hDllModule );
    return ;
}

void FetchProcessHandle::Query( const int Pid, std::function<bool(FetchProcessHandleResult&)> cbFetchResult )
{
    // 返回出错
    if ( !m_pZWQuerySystemInfoformation||!m_pZWQueryObject ) 
    {
        return ;
    }

    // 进行查询
    ULONG BufSize       = 1;
    void* pBuf          = calloc( BufSize, 1 );
    assert( pBuf );
    do 
    {
        // 查询 16 号功能的代码
        NTSTATUS NtStatus = m_pZWQuerySystemInfoformation( SystemHandleInformation, pBuf, BufSize, NULL );
        // 成功
        if ( NT_SUCCESS(NtStatus) ) 
        {
            ULONG NumberOfHandle               = *((PULONG)pBuf);
            SYSTEM_HANDLE_INFORMATION* pResult = (SYSTEM_HANDLE_INFORMATION*)( (PULONG)pBuf+1 );
            OnQuerySucess( Pid, NumberOfHandle, pResult, cbFetchResult );
            break;      
        }
        else 
        {
            // 分配的内存不足
            if ( STATUS_INFO_LENGTH_MISMATCH==NtStatus ) 
            {
                BufSize*=2;
                free( pBuf );
                pBuf = nullptr;
                pBuf = calloc( BufSize, 1 );
            }
            else
            {
                break;
            }
        }
    }while( true );
    free( pBuf );
}

void FetchProcessHandle::OnQuerySucess( const int Pid, ULONG NumberOfHandle, SYSTEM_HANDLE_INFORMATION* pResult, std::function<bool(FetchProcessHandleResult&)> cbFetchResult )
{
    bool bLoop = true;
    for(std::size_t nIndex(0); nIndex<NumberOfHandle&&bLoop; nIndex++)
    {
        if ( pResult[nIndex].ProcessId!=Pid ) continue;
        char szName[MAX_PATH] = {0};
        char szType[128]      = {0};
        DWORD dwFlags = 0;
        // 把远端句柄拷贝到本地进程
        HANDLE hObject = NULL;
        HANDLE hRemoteProcess = OpenProcess( PROCESS_DUP_HANDLE, FALSE, Pid );

        FetchProcessHandleResult FetchResult;
        NTSTATUS NtStatus = m_pZwDuplicateObject( hRemoteProcess, (HANDLE)(pResult[nIndex].Handle), GetCurrentProcess(), &hObject, 0, 0, 0 );
        NtStatus = m_pZWQueryObject( hObject, ObjectNameInformation, (POBJECT_NAME_INFORMATION)szName, MAX_PATH, &dwFlags );
        NtStatus = m_pZWQueryObject( hObject, ObjectTypeInformation, (POBJECT_NAME_INFORMATION)szType, 128, &dwFlags );
        POBJECT_NAME_INFORMATION  pObjName = ((POBJECT_NAME_INFORMATION)szName);
        POBJECT_NAME_INFORMATION  pObjType = ((POBJECT_NAME_INFORMATION)szType);

        FetchResult.ProcessId     = pResult[nIndex].ProcessId;
        FetchResult.GrantedAccess = pResult[nIndex].GrantedAccess;
        FetchResult.Handle        = (HANDLE)pResult[nIndex].Handle;
        FetchResult.Object        = pResult[nIndex].Object;

        assert( sizeof(FetchResult.ObjectName)>pObjName->Name.Length );
        assert( sizeof(FetchResult.ObjType)>pObjType->Name.Length );
        int i(0);
        for( ; i<pObjName->Name.Length; ++i )
        {
            FetchResult.ObjectName[i] = (UCHAR)pObjName->Name.Buffer[i];
        }

        for( i=0;i<pObjType->Name.Length; ++i )
        {
            FetchResult.ObjType[i] = (UCHAR)pObjType->Name.Buffer[i];
        }

        if( !cbFetchResult( FetchResult ) ) 
        {
            bLoop = false;
        }
        CloseHandle( hRemoteProcess );
    }
}
