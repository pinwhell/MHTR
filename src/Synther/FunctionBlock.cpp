#include <MHTR/Synther/FunctionBlock.h>
#include <MHTR/Synther/Line.h>
#include <MHTR/Synther/LineGroup.h>
#include <MHTR/Synther/ScopeBlock.h>
#include <MHTR/Synther/MultiLineGroup.h>

FunctionBlock::FunctionBlock(const std::string& fnName, IMultiLineSynthesizer* fnContentSynther, ILineSynthesizer* argLnSynther, const std::string& returnType, std::string indent)
    : mName(fnName)
    , mContentSynther(fnContentSynther)
    , mArgsSynther(argLnSynther)
    , mReturnType(returnType)
    , mIndent(indent)
{}

std::vector<std::string> FunctionBlock::Synth() const
{
    Line fnSignatureLn(
        mReturnType
        + " "
        + mName
        + "("
        + mArgsSynther->Synth()
        + ")");
    LineSynthesizerGroup fnSignature({
        &fnSignatureLn
        });
    ScopeBlock fnContentBlock(mContentSynther, mIndent);
    MultiLineSynthesizerGroup fullFn({
        &fnSignature,
        &fnContentBlock
        });

    return fullFn.Synth();
}