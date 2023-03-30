#pragma once

#include <iterator>

template <typename Container>
class ContainerDisplacer
{
private:
	typedef typename Container::iterator Iterator;
	typedef typename Container::value_type ValType;
	ValType mDisp;

public:
	void Displace(Iterator begin, Iterator end)
	{
		for (auto it = begin; it < end; it++)
			*it += mDisp;
	}

	void setDisp(ValType disp)
	{
		mDisp = disp;
	}

	ValType getDisp()
	{
		return mDisp;
	}
};
