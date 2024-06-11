#pragma once

#include <string>

class ILineSynthesizer {
public:
    virtual ~ILineSynthesizer() {}
    virtual std::string Synth() const = 0;
};