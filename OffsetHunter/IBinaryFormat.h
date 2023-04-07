#pragma once

#include <cstdint>
#include "ICapstoneHelper.h"
#include "CapstoneHelperProvider.h"

class IBinaryFormat {
	virtual bool MakeCapstoneHelper(CapstoneHelperProvider* pProvider, ICapstoneHelper** outHelper);
};

template<typename T>
class IBinaryFormatImpl : public IBinaryFormat
{
private:
	union {
		uintptr_t mBase;
		void* mVBase;
		T* mFormatBase;
	};

public:
	void setBase(uintptr_t base);
	void setBase(void* base);
	void setBase(T* base);
};

template<typename T>
void IBinaryFormatImpl<T>::setBase(uintptr_t base)
{
	mBase = base;
}

template<typename T>
void IBinaryFormatImpl<T>::setBase(void* base)
{
	mVBase = base;
}

template<typename T>
void IBinaryFormatImpl<T>::setBase(T* base)
{
	mFormatBase = base;
}

