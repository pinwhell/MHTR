#pragma once

#include <MHTR/Synther/ILine.h>
#include <MHTR/Synther/IMultiLine.h>
#include <MHTR/Synther/ScopeBlock.h>
#include <MHTR/Synther/Indent.h>

class IfBlock : public IMultiLineSynthesizer {
public:
    IfBlock(ILineSynthesizer* conditionSynther, IMultiLineSynthesizer* blockContentSynther, std::string indent = IndentMake());

    std::vector<std::string> Synth() const override;

    ILineSynthesizer* mConditionSynther;
    ScopeBlock mScopeBlock;
};