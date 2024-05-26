#pragma once

#include <vector>
#include <string>

class IMultiLineSynthesizer {
public:
    virtual ~IMultiLineSynthesizer() {}
    virtual std::vector<std::string> Synth() const = 0;
};