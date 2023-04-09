#include "OffsetClassifier.h"
#include <unordered_map>

#include "FutureOffset.h"
#include "HardcodedOffsetInfo.h"

void OffsetClassifier::Classify(JsonValueWrapper& metadata, std::unique_ptr<IOffset>& outOffset)
{
    std::unordered_map<std::string, std::vector<std::string>> signatureTypes;

    bool bContainsValue = JSON_ASSERT(metadata, "value");
    bool bContainsCombine = JSON_ASSERT(metadata, "combine");
    bool bContainsPattern = JSON_ASSERT(metadata, "pattern");

    if (bContainsValue == true ||
        bContainsCombine && bContainsPattern == false)
        outOffset = std::move(std::make_unique<HardcodedOffsetInfo>());
    else 
        outOffset = std::move(std::make_unique<FutureOffset>());

    outOffset->setMetadata(metadata);
}
