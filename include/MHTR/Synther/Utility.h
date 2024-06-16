#pragma once

#include <string>
#include <MHTR/Synther/IMultiLine.h>

std::string SingleLinefy(const IMultiLineSynthesizer* contentProvider, const std::string& delimiter = "\n");

inline std::string Literal(const std::string& str)
{
    return "\"" + str + "\"";
}