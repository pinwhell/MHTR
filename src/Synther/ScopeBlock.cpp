#include <Synther/ScopeBlock.h>

ScopeBlock::ScopeBlock(IMultiLineSynthesizer* contentSynther, std::string indent)
    : mContentSynther(contentSynther)
    , mIndent(indent)
{}

std::vector<std::string> ScopeBlock::Synth() const
{
    std::vector<std::string> lines;

    lines.push_back("{");

    std::vector<std::string> content = mContentSynther->Synth();

    for (const auto& line : content)
    {
        lines.push_back(
            mIndent + line
        );
    }

    lines.push_back("}");

    return lines;
}