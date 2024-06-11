#include <MHTR/Binary/Unknown.h>
#include <stdexcept>

std::unique_ptr<ICapstone> UnknownBinary::CreateInstance(bool bDetailedInst)
{
    throw std::logic_error("CreateInstance is not implemented for UnknownBinary.");
}

IFarAddressResolver* UnknownBinary::GetFarAddressResolver(ICapstoneProvider* cstoneProvider)
{
    throw std::logic_error("GetFarAddressResolver is not implemented for UnknownBinary.");
}

Range UnknownBinary::GetRange()
{
    throw std::logic_error("IRangeProvider is not implemented for UnknownBinary.");
}

IOffsetCalculator* UnknownBinary::GetOffsetCalculator()
{
    throw std::logic_error("IOffsetCalculatorProvider is not implemented for UnknownBinary.");
}
