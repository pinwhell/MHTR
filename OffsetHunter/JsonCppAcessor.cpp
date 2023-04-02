#include "JsonCppAcessor.h"

std::string JsonCppAcessor::genGetInt()
{
    return  IJsonAccesor::genJsonAccess() + ".asInt()" + IJsonAccesor::genXorend();
}

std::string JsonCppAcessor::genGetUInt()
{
    return IJsonAccesor::genJsonAccess() + ".asUInt()" + IJsonAccesor::genXorend();
}
