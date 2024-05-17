#pragma once

#include <Synther/IMultiLine.h>

class MultiLineSynthesizerGroup : public IMultiLineSynthesizer {
public:
    MultiLineSynthesizerGroup(const  std::vector<IMultiLineSynthesizer*>& multiLineSynthers = {});

    std::vector<std::string> Synth() const override;

private:
    std::vector<IMultiLineSynthesizer*> mMultiLinesSynthers;
};