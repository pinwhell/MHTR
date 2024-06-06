#pragma once

#include <Synther/ILine.h>

class Line : public ILineSynthesizer {
public:
    Line(const std::string& line);

    // Inherited via ILineSynthesizer
    std::string Synth() const override;

    static Line Empty();

    std::string mLine;
};
