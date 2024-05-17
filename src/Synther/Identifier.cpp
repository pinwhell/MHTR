#include <Synther/Identifier.h>

Identifier::Identifier(const std::string& identifier)
    : mIdentifier(identifier)
{}

std::string Identifier::GetIdentifier() const {
    return mIdentifier;
}