#include <MHTR/Binary/File.h>
#include <MHTR/Binary/Factory.h>

using namespace MHTR;

BinaryFile::BinaryFile(const char* filePath)
	: mFileView(filePath)
	, mFormatedBinary(FromMemoryBinaryFactory(mFileView).CreateBinary())
	, mOffsetCalculator(this)
{}

Range BinaryFile::GetRange() {
	return Range(mFileView, mFileView.size());
}

std::unique_ptr<ICapstone> BinaryFile::CreateInstance(bool bDetailedInst)
{
	return mFormatedBinary->CreateInstance(bDetailedInst);
}

IFarAddressResolver* BinaryFile::GetFarAddressResolver(ICapstoneProvider* cstoneProvider)
{
	return mFormatedBinary->GetFarAddressResolver(cstoneProvider);
}

IOffsetCalculator* BinaryFile::GetOffsetCalculator()
{
	return &mOffsetCalculator;
}
