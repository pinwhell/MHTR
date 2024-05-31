#include <Factory/FromTargetBinJsonBinary.h>
#include <Exception/UnexpectedLayout.h>
#include <Binary/File.h>
#include <fmt/core.h>

FromTargetBinJsonBinaryFactory::FromTargetBinJsonBinaryFactory(IJsonProvider* _json)
{
    const auto& json = (*_json->GetJson());

    if (json.contains("binaryPath") == false)
        throw UnexpectedLayoutException(fmt::format("invalid binary target format"));

    mPath = json["binaryPath"].get<std::string>();
}

std::unique_ptr<IBinary> FromTargetBinJsonBinaryFactory::CreateBinary()
{
    return std::make_unique<BinaryFile>(mPath.c_str());
}