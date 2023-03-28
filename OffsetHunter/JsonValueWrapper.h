#pragma once

#include <json/json.h>
#include "JsonHelper.h"

class JsonValueWrapper : public Json::Value
{
public:

	JsonValueWrapper();
	JsonValueWrapper(Json::Value& json);

	template<typename T>
	T get(const std::string& key, T def);

	template<>
	std::string get(const std::string& key, std::string def);

	template<>
	int get(const std::string& key, int def);

	Json::Value& getJsonValue();

};


template<typename T>
inline T JsonValueWrapper::get(const std::string& key, T def)
{}

template<>
inline std::string JsonValueWrapper::get(const std::string& key, std::string def)
{
	if (JSON_ASSERT(*this, key))
		return def;

	return (*this)[key].asString();
}

template<>
inline int JsonValueWrapper::get(const std::string& key, int def)
{
	if (JSON_ASSERT(*this, key))
		return def;

	return (*this)[key].asInt();
}


