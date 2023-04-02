#pragma once

#include <string>

class IJsonAccesor {

private:
    std::string mJsonObjName;
    std::string mKey;

protected:
    uint32_t mXorend;

public:
    virtual std::string genGetInt();
    virtual std::string genGetUInt();

    std::string genJsonAccess();

    void setXorend(uint32_t xorend);
    void setJsonObjectName(const std::string& jsonObjName);
    void setKey(const std::string& key);

    std::string genXorend();
};

