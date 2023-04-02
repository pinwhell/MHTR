#pragma once


template<typename T>
class IChild
{
protected:
	T* mParent;

public:
	void setParent(T* parent)
	{
		mParent = parent;
	}

	T* getParent()
	{
		return mParent;
	}
};

