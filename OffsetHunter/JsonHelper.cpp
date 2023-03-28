#include "JsonHelper.h"
#include <fstream>
#include "FileHelper.h"

bool JsonHelper::String2Json(const std::string& fullJsonStr, Json::Value& outJson)
{
    Json::CharReaderBuilder charReaderBuilder;
    Json::IStringStream stringStream = Json::IStringStream(fullJsonStr);
    
    return Json::parseFromStream(charReaderBuilder, stringStream, &outJson, nullptr);
}

bool JsonHelper::Json2File(const Json::Value& jsonRoot, const std::string& outPath)
{
    Json::FastWriter fw;

    std::string jsonStr = fw.write(jsonRoot);

    std::ofstream fTrait(outPath);

    if (fTrait.is_open())
    {
        fTrait.clear();
        fTrait << jsonStr;
        fTrait.close();

        return true;
    }

    return false;
}

bool JsonHelper::File2Json(const std::string& filePath, Json::Value& outJson)
{
    std::string fullFileContent = "";

    if (FileHelper::ReadFile(filePath, fullFileContent) == false)
        return false;

    return String2Json(fullFileContent, outJson);
}
