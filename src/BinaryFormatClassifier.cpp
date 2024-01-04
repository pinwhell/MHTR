#include <OH/BinaryFormatClassifier.h>
#include <OH/ELF32BinaryFormat.h>
#include <OH/UnknownBinaryFormat.h>
#include <OH/ELFHelper.h>

bool BinaryFormatClassifier::Classify(unsigned char* bin, std::unique_ptr<IBinaryFormat>& outBinFormat, bool bSetBinAsBase)
{
    if (ELFHelper::IsELF(bin))
    {
        if (ELFHelper::Is32(bin))
            outBinFormat = std::make_unique<ELF32BinaryFormat>();
    }

    if (!(outBinFormat)) //if we wasnt able to classify it
        outBinFormat = std::make_unique<UnknownBinaryFormat>();
       
    if (bSetBinAsBase)
        outBinFormat->setBase(bin);

    return true;
}

bool BinaryFormatClassifier::Classify(std::string& binFormat, std::unique_ptr<IBinaryFormat>& outBinFormat, unsigned char* bin)
{
    if (binFormat.empty())
    {
        if (bin == nullptr)
            return false;

        return Classify(bin, outBinFormat);
    }
        

    if (binFormat == "elf32")
        outBinFormat = std::make_unique<ELF32BinaryFormat>();

    outBinFormat = std::make_unique<UnknownBinaryFormat>();

    outBinFormat->setBase(bin);

    return true;
}
