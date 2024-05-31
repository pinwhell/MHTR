#include <Provider/FromJsonPathJsonFile.h>
#include <Exception/UnexpectedLayout.h>
#include <fmt/core.h>

FromJsonPathJsonFileProvider::FromJsonPathJsonFileProvider(IJsonProvider* jsonContainingPath, const std::string& jsonPathKey)
    : mProvider([jsonContainingPath, &jsonPathKey] {
    const auto& json = (*jsonContainingPath->GetJson());

    if (json.contains(jsonPathKey) == false)
        throw UnexpectedLayoutException(fmt::format("path with key '{}' not found", jsonPathKey));

    return json[jsonPathKey].get<std::string>();
        }())
{}

nlohmann::json* FromJsonPathJsonFileProvider::GetJson()
{
    return mProvider.GetJson();
}