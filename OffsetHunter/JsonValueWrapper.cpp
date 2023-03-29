#include "JsonValueWrapper.h"

JsonValueWrapper::JsonValueWrapper()
{
}

JsonValueWrapper::JsonValueWrapper(Json::Value& json)
{
	*(Json::Value*)this = json;
}

const Json::Value& JsonValueWrapper::getJsonValue() const
{
	return *this;
}
