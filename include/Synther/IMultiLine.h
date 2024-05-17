#pragma once

#include <vector>
#include <string>

class IMultiLineSynthesizer {
public:
    virtual std::vector<std::string> Synth() const = 0;
};