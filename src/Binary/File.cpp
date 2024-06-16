#include <Binary/File.h>
#include <Binary/Factory.h>

BinaryFile::BinaryFile(const char* filePath, IBinaryArchModeProvider* binaryArchModeProvider)
	: mBinaryArchModeProvider(binaryArchModeProvider)
	, mFileView(filePath)
	, mFormatedBinary(FromMemoryBinaryFactory(mFileView, mBinaryArchModeProvider).CreateBinary())
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
