#pragma once

#include <Synther/ILine.h>
#include <Synther/IMultiLine.h>

class LineSynthesizerGroup : public IMultiLineSynthesizer {
public:
    LineSynthesizerGroup(const  std::vector<ILineSynthesizer*>& lineSynthers = {});

    std::vector<std::string> Synth() const override;

private:
    std::vector<ILineSynthesizer*> mLineSynthers;
};