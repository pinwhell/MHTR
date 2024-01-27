#include <OH/IJsonAccesor.h>

std::string IJsonAccesor::genGetInt(const std::string& key, uint32_t xorend)
{
    return genJsonAccess(key) + genXorend(xorend);
}

std::string IJsonAccesor::genGetUInt(const std::string& key, uint32_t xorend)
{
    return genJsonAccess(key) + genXorend(xorend);
}

std::string IJsonAccesor::genAssign(const std::string& key, const std::string& what)
{
    return genJsonAccess(key) + " = " + what + ";";
}

std::string IJsonAccesor::genJsonAccess(const std::string& key)
{
    return mJsonObjName + "[\"" + key + "\"]";
}

void IJsonAccesor::setJsonObjectName(const std::string& jsonObjName)
{
    mJsonObjName = jsonObjName;
}

std::string IJsonAccesor::genXorend(uint32_t xorend)
{
    return xorend != 0 ? (" ^ " + std::to_string(xorend)) : "";
}

std::string IJsonAccesor::getGlobalInclude()
{
    return "";
}

std::string IJsonAccesor::getJsonObjFullType()
{
    return "";
}

std::string IJsonAccesor::getJsonObjectName()
{
    return mJsonObjName;
}
