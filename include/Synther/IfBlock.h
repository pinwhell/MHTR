#pragma once

#include <Synther/ILine.h>
#include <Synther/IMultiLine.h>
#include <Synther/ScopeBlock.h>
#include <Synther/Indent.h>

class IfBlock : public IMultiLineSynthesizer {
public:
    IfBlock(ILineSynthesizer* conditionSynther, IMultiLineSynthesizer* blockContentSynther, std::string indent = IndentMake());

    std::vector<std::string> Synth() const override;

    ILineSynthesizer* mConditionSynther;
    ScopeBlock mScopeBlock;
};