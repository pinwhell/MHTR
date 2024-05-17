#include <Synther/Line.h>

Line::Line(const std::string& line)
    : mLine(line)
{}

std::string Line::Synth() const
{
    return mLine;
}