#include <unordered_map>

#include <OH/FutureResultClassifier.h>
#include <OH/FutureOffset.h>
#include <OH/HardcodedOffsetInfo.h>

void FutureResultClassifier::Classify(JsonValueWrapper& metadata, std::unique_ptr<IFutureResult>& outOffset)
{
    std::unordered_map<std::string, std::vector<std::string>> signatureTypes;

    bool bContainsValue = JSON_ASSERT(metadata, "value");
    bool bContainsCombine = JSON_ASSERT(metadata, "combine");
    bool bContainsPattern = JSON_ASSERT(metadata, "pattern");

    /*Hardcoded*/
    int hardcodedResultInfoScore = 0;
    
    if (bContainsCombine == true)
        hardcodedResultInfoScore += 1;

    if (bContainsValue == true)
        hardcodedResultInfoScore += 1;

    if (bContainsPattern == true)
        hardcodedResultInfoScore -= 1;

    /*Finded*/
    int FutureOffsetScore = 0;

    /*Hardcoded*/
    if (bContainsCombine == true)
        FutureOffsetScore += 1;

    if (bContainsValue == true)
        FutureOffsetScore += 1;

    if (bContainsPattern == true)
        FutureOffsetScore += 1;


    if (FutureOffsetScore > hardcodedResultInfoScore)
        outOffset = std::move(std::make_unique<FutureOffset>());
    else  
        outOffset = std::move(std::make_unique<HardcodedResultInfo>());


    outOffset->setMetadata(metadata);
}
