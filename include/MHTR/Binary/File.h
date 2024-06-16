#pragma once

#include <MHTR/Provider/IBinaryArchMode.h>
#include <MHTR/Binary/IBinary.h>
#include <MHTR/Binary/Factory.h>
#include <MHTR/File/View.h>
#include <MHTR/OffsetCalculator.h>

namespace MHTR {
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
}