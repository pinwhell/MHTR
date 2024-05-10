#pragma once

#include <stdexcept>
#include <string>
#include <vector>

class MultiException : public std::runtime_error {
public:
    MultiException(const std::vector<std::string>& exceptions);

    virtual const char* what() const noexcept override;

private:
    std::vector<std::string> mExceptions;
    mutable std::string mFullException; // Mutable to allow modification in const method
};