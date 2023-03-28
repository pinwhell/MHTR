#include "JsonValueWrapper.h"

JsonValueWrapper::JsonValueWrapper()
{
}

JsonValueWrapper::JsonValueWrapper(Json::Value& json)
{
	*(Json::Value*)this = json;
}

Json::Value& JsonValueWrapper::getJsonValue()
{
	return *this;
}
