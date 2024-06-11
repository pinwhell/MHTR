#pragma once

#include <MHTR/Synther/IIdentifier.h>

class Identifier : public IIdentifier {
public:
    Identifier(const std::string& identifier);

    std::string GetIdentifier() const override;

    std::string mIdentifier;
};