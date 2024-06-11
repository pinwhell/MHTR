#pragma once

#include <MHTR/Synther/IMultiLine.h>
#include <MHTR/Synther/Indent.h>

class ScopeBlock : public IMultiLineSynthesizer {
public:
    ScopeBlock(IMultiLineSynthesizer* contentSynther, std::string indent = IndentMake());

    std::vector<std::string> Synth() const override;

    IMultiLineSynthesizer* mContentSynther;
    std::string mIndent;
};