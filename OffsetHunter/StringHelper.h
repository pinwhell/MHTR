#pragma once

#include <vector>
#include <string>

class StringHelper
{
public:
	static std::vector<std::string> Tokenize(std::string str, char delim);
	static std::string Capitalize(const std::string& str);
	static std::string Unify(const std::vector<std::string>& vecStrs);
};

