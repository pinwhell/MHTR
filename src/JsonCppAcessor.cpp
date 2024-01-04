#include <OH/JsonCppAcessor.h>

std::string JsonCppAcessor::genGetInt(const std::string& key, uint32_t xorend)
{
    return  IJsonAccesor::genJsonAccess(key) + ".asInt()" + IJsonAccesor::genXorend(xorend);
}

std::string JsonCppAcessor::genGetUInt(const std::string& key, uint32_t xorend)
{
    return IJsonAccesor::genJsonAccess(key) + ".asUInt()" + IJsonAccesor::genXorend(xorend);
}

std::string JsonCppAcessor::getGlobalInclude()
{
    return "json/json.h";
}

std::string JsonCppAcessor::getJsonObjFullType()
{
    return "Json::Value";
}
