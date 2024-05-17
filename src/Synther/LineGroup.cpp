#include <Synther/LineGroup.h>

LineSynthesizerGroup::LineSynthesizerGroup(const std::vector<ILineSynthesizer*>& lineSynthers)
    : mLineSynthers(lineSynthers)
{}

std::vector<std::string> LineSynthesizerGroup::Synth() const
{
    std::vector<std::string> lines;

    for (const auto lineSynther : mLineSynthers)
        lines.push_back(lineSynther->Synth());

    return lines;
}