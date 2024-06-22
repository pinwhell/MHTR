#pragma once

#include <MHTR/Synther/IMultiLine.h>
#include <MHTR/Synther/Line.h>

class MultiLineSingleLine : public IMultiLineSynthesizer {
public:
    MultiLineSingleLine(const Line& line);

    MultiLine Synth() const override;

    Line mLine;

    static MultiLineSingleLine mEmpty;
    static MultiLineSingleLine mEmptyLine;
};