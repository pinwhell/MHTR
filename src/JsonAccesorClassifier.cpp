#include <OH/JsonAccesorClassifier.h>
#include <OH/JsonCppAcessor.h>

bool JsonAccesorClassifier::Classify(const std::string& jsonLib, std::unique_ptr<IJsonAccesor>& outObj)
{

    if (jsonLib == "jsoncpp")
    {
        outObj = std::move(std::make_unique<JsonCppAcessor>());
        return true;
    }

    return false;
}
