#include <MHTR/Synther/LineGroup.h>

LineGroup::LineGroup(const std::vector<std::string>& lines)
    : mLines(lines)
{}

std::vector<std::string> LineGroup::Synth() const {
    return mLines;
}

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