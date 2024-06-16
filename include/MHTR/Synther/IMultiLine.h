#pragma once

#include <vector>
#include <string>

using MultiLine = std::vector<std::string>;

class IMultiLineSynthesizer {
public:
    virtual ~IMultiLineSynthesizer() {}
    virtual MultiLine Synth() const = 0;
};