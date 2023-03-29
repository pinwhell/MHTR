#pragma once

#include <string>
#include <vector>

namespace FileHelper
{
	bool IsValidFilePath(const std::string& filePath, bool logPathUnacesible = false, bool logPathIsNotRegularFile = false);
	bool ReadFile(const std::string& filePath, std::string& output);
	bool ReadFileBinary(const std::string& filePath, std::vector<unsigned char>& output);
}

