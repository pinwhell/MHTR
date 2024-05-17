#pragma once

#include <Synther/IMultiLine.h>
#include <Synther/ScopeBlock.h>

class NamespaceBlock : public IMultiLineSynthesizer {
public:
    NamespaceBlock(IMultiLineSynthesizer* blockContentSynther, const std::string& name = "", std::string indent = IndentMake());

    std::vector<std::string> Synth() const override;

    std::string mName;
    ScopeBlock mScopeBlock;
};