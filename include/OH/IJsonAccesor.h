#pragma once

#include <string>

class IJsonAccesor {

private:
    std::string mJsonObjName;

protected:

public:
    virtual std::string genGetInt(const std::string& key, uint32_t xorend = 0x0);
    virtual std::string genGetUInt(const std::string& key, uint32_t xorend = 0x0);
    virtual std::string genAssign(const std::string& key, const std::string& what);

    std::string genJsonAccess(const std::string& key);

    void setJsonObjectName(const std::string& jsonObjName);

    std::string genXorend(uint32_t xorend = 0x0);

    virtual std::string getGlobalInclude();

    virtual std::string getJsonObjFullType(); // for example in the scenario of JsonCPP library
                                              // it will return "Json::Value"

    std::string getJsonObjectName();
};

