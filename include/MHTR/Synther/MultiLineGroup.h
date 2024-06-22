#pragma once

#include <MHTR/Synther/IMultiLine.h>

class MultiLineSynthesizerGroup : public IMultiLineSynthesizer {
public:
    MultiLineSynthesizerGroup(const std::vector<IMultiLineSynthesizer*>& multiLineSynthers = {});

    std::vector<std::string> Synth() const override;

    static MultiLineSynthesizerGroup mEmpty;

private:
    std::vector<IMultiLineSynthesizer*> mMultiLinesSynthers;
};