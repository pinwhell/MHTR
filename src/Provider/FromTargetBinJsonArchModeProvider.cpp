#include <MHTR/Provider/FromTargetBinJsonArchModeProvider.h>

using namespace MHTR;

FromTargetBinJsonArchModeProvider::FromTargetBinJsonArchModeProvider(IJsonProvider* binTargetJson)
    : mMode([binTargetJson] {
    const auto& json = (*binTargetJson->GetJson());
    return json.contains("binaryArchMode") == false ?
        ECapstoneArchMode::UNDEFINED :
        ECapstoneArchModeFromString(
            json["binaryArchMode"].get<std::string>()
        );
        }())
{}

ECapstoneArchMode FromTargetBinJsonArchModeProvider::GetBinaryArchMode()
{
    return mMode;
}
