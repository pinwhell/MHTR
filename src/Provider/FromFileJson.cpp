#include <fstream>
#include <MHTR/Provider/FromFileJson.h>

using namespace MHTR;

FromFileJsonProvider::FromFileJsonProvider(const std::string& filePath)
    : mJson(nlohmann::json::parse(std::ifstream(filePath)))
{}

nlohmann::json* FromFileJsonProvider::GetJson()
{
    return &mJson;
}