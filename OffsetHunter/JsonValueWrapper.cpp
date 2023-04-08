#include "JsonValueWrapper.h"

std::mutex JsonValueWrapper::mOpMtx;

JsonValueWrapper::JsonValueWrapper()
{}

JsonValueWrapper::JsonValueWrapper(Json::Value& json)
	: Json::Value(json)
{}

const Json::Value& JsonValueWrapper::getJsonValue() const
{
	return *this;
}
