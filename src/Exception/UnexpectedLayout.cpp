#include <MHTR/Exception/UnexpectedLayout.h>

UnexpectedLayoutException::UnexpectedLayoutException(const std::string& what)
    : std::runtime_error(what)
{}
