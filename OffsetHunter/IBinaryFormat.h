#pragma once

#include <cstdint>
#include "ICapstoneHelper.h"
#include "CapstoneHelperProvider.h"

class IBinaryFormat {

private:
	union {
		uintptr_t mBase;
		void* mVBase;
	};

public:
	virtual bool MakeCapstoneHelper(CapstoneHelperProvider* pProvider, ICapstoneHelper** outHelper);

	void setBase(uintptr_t base);
	void setBase(void* base);
};

template<typename T>
class IBinaryFormatImpl : public IBinaryFormat
{
public:
	void setBase(T* base);
};

template<typename T>
void IBinaryFormatImpl<T>::setBase(T* base)
{
	setBase((void*)base);
}

