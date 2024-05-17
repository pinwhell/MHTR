#include <Synther/IfBlock.h>

IfBlock::IfBlock(ILineSynthesizer* conditionSynther, IMultiLineSynthesizer* blockContentSynther, std::string indent)
    : mConditionSynther(conditionSynther)
    , mScopeBlock(blockContentSynther, indent)
{}

std::vector<std::string> IfBlock::Synth() const
{
    std::vector<std::string> block = mScopeBlock.Synth();

    block[0] = "if(" + mConditionSynther->Synth() + ") " + block[0];

    return block;
}