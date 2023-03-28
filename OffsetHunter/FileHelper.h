#pragma once

#include <string>

namespace FileHelper
{
	bool IsValidFilePath(const std::string& filePath, bool logPathUnacesible = false, bool logPathIsNotRegularFile = false);
	bool ReadFile(const std::string& filePath, std::string& output);
}

