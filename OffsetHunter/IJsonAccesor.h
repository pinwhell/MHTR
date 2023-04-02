#pragma once

#include <string>

class IJsonAccesor {

private:
    std::string mJsonObjName;

protected:

public:
    virtual std::string genGetInt(const std::string& key, uint32_t xorend = 0x0);
    virtual std::string genGetUInt(const std::string& key, uint32_t xorend = 0x0);

    std::string genJsonAccess(const std::string& key);

    void setJsonObjectName(const std::string& jsonObjName);

    std::string genXorend(uint32_t xorend = 0x0);

    virtual std::string getGlobalInclude();
};

