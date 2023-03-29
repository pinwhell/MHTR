#pragma once

#include <json/json.h>

class JsonHelper
{
public:
	static bool String2Json(const std::string& fullJsonStr, Json::Value& outJson);
	static bool Json2File(const Json::Value& jsonRoot, const std::string& outPath);
	static bool File2Json(const std::string& filePath, Json::Value& outJson);
};

#define JSON_IS_MEMBER(json, key) ((json).isMember(key))
#define JSON_ASSERT(json, key) (JSON_IS_MEMBER((json), key)) // True if valid
#define JSON_ASSERT_STR_EMPTY(json, key) (JSON_ASSERT(json, key) == true ? ((json)[key].asString().empty() == false) : false) // True if valid
