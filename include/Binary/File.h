#pragma once

#include <Provider/IBinaryArchMode.h>
#include <Binary/IBinary.h>
#include <Binary/Factory.h>
#include <File/View.h>
#include <OffsetCalculator.h>

class BinaryFile : public IBinary {
public:
	BinaryFile(const char* filePath, IBinaryArchModeProvider* binaryArchModeProvider = 0);

	Range GetRange() override;
	std::unique_ptr<ICapstone> CreateInstance(bool bDetailedInst = true) override;
	IFarAddressResolver* GetFarAddressResolver(ICapstoneProvider* cstoneProvider) override;
	IOffsetCalculator* GetOffsetCalculator() override;

private:
	IBinaryArchModeProvider* mBinaryArchModeProvider;
	FileView mFileView;
	std::unique_ptr<IBinary> mFormatedBinary;
	OffsetCalculator mOffsetCalculator;
};