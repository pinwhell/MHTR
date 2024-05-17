#pragma once

#include <string>

class ILineSynthesizer {
public:
    virtual std::string Synth() const = 0;
};