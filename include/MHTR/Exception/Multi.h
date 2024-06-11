#pragma once

#include <stdexcept>
#include <vector>
#include <string>

class MultiException : public std::runtime_error {
public:
	MultiException(const std::vector<std::string>& exceptions);

	const char * what() const noexcept override;

	mutable std::string mFullException;
	std::vector<std::string> mExceptions;
};