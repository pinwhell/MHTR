#pragma once

#include <iterator>


class ContainerDisplacer
{
private:
	
	//ValType mDisp;

public:
	template <typename Container, typename Displacer>
	static void Displace(typename Container::iterator begin, typename Container::iterator end, Displacer disp)
	{
		for (auto it = begin; it < end; it++)
		{
			auto curr = *it;
			Displacer _new = (Displacer)curr + disp;
			*it = _new;
		}
	}

	/*void setDisp(ValType disp)
	{
		mDisp = disp;
	}

	ValType getDisp()
	{
		return mDisp;
	}*/
};
