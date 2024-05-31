#pragma once

#include <Provider/FromFileJson.h>
#include <fstream>

FromFileJsonProvider::FromFileJsonProvider(const std::string& filePath)
    : mJson(nlohmann::json::parse(std::ifstream(filePath)))
{}

nlohmann::json* FromFileJsonProvider::GetJson()
{
    return &mJson;
}