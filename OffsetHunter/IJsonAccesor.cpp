#include "IJsonAccesor.h"

std::string IJsonAccesor::genGetInt()
{
    return genJsonAccess() + genXorend();
}

std::string IJsonAccesor::genGetUInt()
{
    return genJsonAccess() + genXorend();
}

std::string IJsonAccesor::genJsonAccess()
{
    return mJsonObjName + "[\"" + mKey + "\"]";
}

void IJsonAccesor::setJsonObjectName(const std::string& jsonObjName)
{
    mJsonObjName = jsonObjName;
}

void IJsonAccesor::setXorend(uint32_t xorend)
{
    mXorend = xorend;
}

void IJsonAccesor::setKey(const std::string& key)
{
    mKey = key;
}

std::string IJsonAccesor::genXorend()
{
    return mXorend != 0 ? (" ^ " + std::to_string(mXorend)) : "";
}
