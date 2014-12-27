#include <Windows.h>
#include "FetchProcessHandle.h"
#include <regex>


/*
    �ûص��Ѷ�Ӧ���̵�����handle���ص�����
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
    FetchProcessHandle( 8384/*������д��Ľ���IP*/, std::bind(test,std::placeholders::_1) );
    return TRUE;
}