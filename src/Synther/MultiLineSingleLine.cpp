#include <MHTR/Synther/MultiLineSingleLine.h>

MultiLineSingleLine MultiLineSingleLine::mEmptyLine(Line(""));

MultiLineSingleLine::MultiLineSingleLine(const Line& line)
    : mLine(line)
{}

MultiLine MultiLineSingleLine::Synth() const
{
    return {
        mLine.Synth()
    };
}