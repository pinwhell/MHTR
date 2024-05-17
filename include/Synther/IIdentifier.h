#pragma once

#include <string>

class IIdentifier {
public:
    virtual std::string GetIdentifier() const = 0;
};