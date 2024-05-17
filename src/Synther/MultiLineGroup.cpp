#include <Synther/MultiLineGroup.h>

MultiLineSynthesizerGroup::MultiLineSynthesizerGroup(const std::vector<IMultiLineSynthesizer*>& multiLineSynthers)
    : mMultiLinesSynthers(multiLineSynthers)
{}

std::vector<std::string> MultiLineSynthesizerGroup::Synth() const
{
    std::vector<std::string> allLines;

    for (const auto multiLineSynther : mMultiLinesSynthers)
    {
        std::vector<std::string> lines = multiLineSynther->Synth();
        allLines.insert(allLines.end(), lines.begin(), lines.end());
    }

    return allLines;
}