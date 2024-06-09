#pragma once

#include <string>

#include <Synther/ILine.h>
#include <Synther/IMultiLine.h>
#include <Synther/Indent.h>

class FunctionBlock : public IMultiLineSynthesizer {
public:
    FunctionBlock(
        const std::string& fnName,
        IMultiLineSynthesizer* fnContentSynther,
        ILineSynthesizer* argLnSynther,
        const std::string& returnType,
        std::string indent = IndentMake()
    );

    std::vector<std::string> Synth() const override;

    std::string mName;
    IMultiLineSynthesizer* mContentSynther;
    ILineSynthesizer* mArgsSynther;
    std::string mReturnType;
    std::string mIndent;
};