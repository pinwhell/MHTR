#pragma once

#include <utility>

namespace MHTR {
	template<typename T>
	class Singleton {
	public:
		template<typename... Args>
		T& Instance(Args&&... args)
		{
			static T instance(std::forward<Args>(args)...);
			return instance;
		}
	};
}
