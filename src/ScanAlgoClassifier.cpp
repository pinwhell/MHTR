#include <OH/ScanAlgoClassifier.h>
#include <OH/PlainPatternScanAlgo.h>
#include <OH/NestedPatternScanAlgo.h>

bool ScanAlgoClassifier::Classify(const JsonValueWrapper& mtdInfo, std::unique_ptr<IOffsetScanAlgo>& outScanAlgo)
{
    std::string methodName = mtdInfo.get<std::string>("method", "std");

    if (methodName == "std")
        outScanAlgo = std::move(std::make_unique<PlainPatternScanAlgo>());
    else if (methodName == "npf") // Nested Pattern Finder
        outScanAlgo = std::move(std::make_unique<NestedPatternScanAlgo>());
    else return false;

    outScanAlgo->setAlgoMetadata(mtdInfo);

    return true;
}
