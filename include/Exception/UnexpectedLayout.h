#pragma once

#include <string>
#include <stdexcept>

class UnexpectedLayoutException : public std::runtime_error {
public:
    UnexpectedLayoutException(const std::string& what);
};