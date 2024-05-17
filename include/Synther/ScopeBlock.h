#pragma once

#include <Synther/IMultiLine.h>
#include <Synther/Indent.h>

class ScopeBlock : public IMultiLineSynthesizer {
public:
    ScopeBlock(IMultiLineSynthesizer* contentSynther, std::string indent = IndentMake());

    std::vector<std::string> Synth() const override;

    IMultiLineSynthesizer* mContentSynther;
    std::string mIndent;
};