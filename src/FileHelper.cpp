#include <OH/FileHelper.h>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

bool FileHelper::FileExist(const std::string& filePath)
{
	return fs::exists(filePath);
}

bool FileHelper::IsValidFilePath(const std::string& filePath, bool logPathUnacesible, bool logPathIsNotRegularFile)
{
	if (filePath.empty() == true)
		return false;

	if (fs::exists(filePath) == false)
	{
		if (logPathUnacesible)
			std::cout << "\"" << filePath << "\" Does not exist or is inaccesible\n";

		return false;
	}

	if (fs::is_regular_file(filePath) == false)
	{
		if (logPathIsNotRegularFile)
			std::cout << "\"" << filePath << "\" is not a file\n";

		return false;
	}

	return true;
}

bool FileHelper::ReadFile(const std::string& filePath, std::string& output)
{
	std::ifstream file(filePath);

	if (file.is_open() == false)
		return false;

	/* By chat GPT =) */
	// read the entire file into a stringstream
	std::stringstream buffer;

	buffer << file.rdbuf();

	// extract the string from the stringstream
	output = buffer.str();

	file.close();

	return true;
}

bool FileHelper::ReadFileBinary(const std::string& filePath, std::vector<unsigned char>& output)
{
	std::ifstream file(filePath, std::ios::binary);

	if (file.is_open() == false)
		return false;

	output = std::vector<unsigned char>(std::istreambuf_iterator<char>(file), {});

	file.close();

	return true;
}

