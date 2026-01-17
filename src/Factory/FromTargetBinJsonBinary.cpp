#include <format>
#include <MHTR/Factory/FromTargetBinJsonBinary.h>
#include <MHTR/Exception/UnexpectedLayout.h>
#include <MHTR/Binary/File.h>

using namespace MHTR;

FromTargetBinJsonBinaryFactory::FromTargetBinJsonBinaryFactory(IJsonProvider* _json, IBinaryArchModeProvider* archModeProvider)
    : mArchModeProvider(archModeProvider)
{
    const auto& json = (*_json->GetJson());

    if (json.contains("binaryPath") == false)
        throw UnexpectedLayoutException(std::format("invalid binary target format"));

    mPath = json["binaryPath"].get<std::string>();
}

std::unique_ptr<IBinary> FromTargetBinJsonBinaryFactory::CreateBinary()
{
    return std::make_unique<BinaryFile>(mPath.c_str(), mArchModeProvider);
}