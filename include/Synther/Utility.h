#pragma once

#include <string>
#include <Synther/IMultiLine.h>

std::string SingleLinefy(const IMultiLineSynthesizer* contentProvider, const std::string& delimiter = "\n");