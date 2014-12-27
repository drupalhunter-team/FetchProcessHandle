#include <Windows.h>
#include "FetchProcessHandle.h"
#include <regex>


/*
    该回调把对应进程的所有handle都回调过来
*/
bool test( FetchProcessHandleResult& pResult )
{
    std::string stdName = (char*)pResult.ObjectName;
    std::smatch m;
    std::regex e ("\\\\BaseNamedObjects\\\\\\{\\S{36}\\}");  
    if ( std::regex_search (stdName,m,e) )
    {
       pResult.ReleaseMutant();
    }
    return true;
}

int main(int argc,char **argv)
{
    FetchProcessHandle( 8384/*这里填写你的进程IP*/, std::bind(test,std::placeholders::_1) );
    return TRUE;
}