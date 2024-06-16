#pragma once

#include <MHTR/Synther/ILine.h>
#include <MHTR/Synther/IMultiLine.h>

class LineGroup : public IMultiLineSynthesizer {
public:
    LineGroup(const std::vector<std::string>& lines);

    std::vector<std::string> Synth() const override;

    std::vector<std::string> mLines;
};

class LineSynthesizerGroup : public IMultiLineSynthesizer {
public:
    LineSynthesizerGroup(const  std::vector<ILineSynthesizer*>& lineSynthers = {});

    std::vector<std::string> Synth() const override;

private:
    std::vector<ILineSynthesizer*> mLineSynthers;
};