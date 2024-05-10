#include <MultiException.h>
#include <sstream>

MultiException::MultiException(const std::vector<std::string>& exceptions)
    : std::runtime_error(""), mExceptions(exceptions) {}

const char* MultiException::what() const noexcept {
    std::stringstream ss;

    for (size_t i = 0; i < mExceptions.size(); ++i)
        ss << "\n" << mExceptions[i];

    mFullException = ss.str();

    return mFullException.c_str();
}