#pragma once

#include <vector>
#include <string>
#include <functional>

class StringHelper
{
public:
	static std::vector<std::string> Tokenize(std::string str, char delim);
	static std::string Capitalize(const std::string& str);
	static std::string Unify(const std::vector<std::string>& vecStrs);
	static std::string ToHexString(uint64_t v);
	static std::string ReplacePlaceHolders(const std::string& input, std::function<std::string(std::string)> onPlaceHolderAboutReplace);
};

