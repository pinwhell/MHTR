#pragma once

#include <stdexcept>
#include <vector>
#include <string>

class MultiException : public std::runtime_error {
public:
	MultiException(const std::vector<std::string>& exceptions);

	char const* what() const override;

	mutable std::string mFullException;
	std::vector<std::string> mExceptions;
};