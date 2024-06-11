#include <MHTR/Exception/UnexpectedLayout.h>

using namespace MHTR;

UnexpectedLayoutException::UnexpectedLayoutException(const std::string& what)
    : std::runtime_error(what)
{}
