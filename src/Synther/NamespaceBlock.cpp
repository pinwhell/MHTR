#include <Synther/NamespaceBlock.h>

NamespaceBlock::NamespaceBlock(IMultiLineSynthesizer* blockContentSynther, const std::string& name, std::string indent)
    : mName(name)
    , mScopeBlock(blockContentSynther, indent)
{}

std::vector<std::string> NamespaceBlock::Synth() const
{
    std::vector<std::string> block = mScopeBlock.Synth();

    if (!mName.empty())
        block[0] = "namespace " + mName + " " + block[0];
    else
        block[0] = "namespace " + block[0];


    return block;
}
