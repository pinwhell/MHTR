#include <OH/StringHelper.h>

#include <sstream>

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

std::string StringHelper::ToHexString(uint64_t v)
{
    std::stringstream sstream;

    sstream  << "0x"  << std::hex << v;

    return sstream.str();
}

std::string StringHelper::ReplacePlaceHolders(const std::string& input, std::function<std::string(std::string)> onPlaceHolderAboutReplace)
{
    std::string result = "";
    std::string acum = "";

    for (const char* c = input.c_str(); c < input.c_str() + input.size(); c++)
    {
        if (c + 1 < input.c_str() + input.size())
        {
            if (c[0] == '#' && c[1] == '(')
            {
                c += 2;
                result += acum;
                acum.clear();
            }
            else if (c[0] == ')' && c[1] == '#')
            {
                c += 2;
                result += onPlaceHolderAboutReplace(acum);
                acum.clear();
            }
        }

        acum += *c;
    }

    result += acum;

    return result;
}
