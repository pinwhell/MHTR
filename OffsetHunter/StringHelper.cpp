#include "StringHelper.h"

std::vector<std::string> StringHelper::Tokenize(std::string str, char delim)
{
    std::vector<std::string> tokens;
    std::string currToken = "";

    for (char c : str)
    {
        if (c == delim)
        {
            tokens.push_back(currToken);
            currToken.clear();
        }
        else currToken += c;
    }

    tokens.push_back(currToken);

    return tokens;
}

std::string StringHelper::Capitalize(const std::string& str)
{
    std::string result = str;

    result[0] = toupper(result[0]);

    return result;
}

std::string StringHelper::Unify(const std::vector<std::string>& vecStrs)
{
    std::string result = "";

    for (const std::string& currStr : vecStrs)
        result += currStr;

    return result;
}
