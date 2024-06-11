#pragma once

#include <string>
#include <stdexcept>

namespace MHTR {
    class UnexpectedLayoutException : public std::runtime_error {
    public:
        UnexpectedLayoutException(const std::string& what);
    };
}