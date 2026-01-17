#include <MHTR/Provider/IProvider.h>
#include <CStone/Factory.h>
#include <CStone/Provider.h>

namespace MHTR {
	struct CapstoneFactoryAndProvider : public ICapstoneProvider, public IProvider {
		CapstoneFactory mFactory;
		CapstoneConcurrentProvider mConcurrentProvider;
		
		inline CapstoneFactoryAndProvider(ECapstoneArchMode arch)
			: mFactory(arch)
			, mConcurrentProvider(&mFactory)
		{}

		inline ICapstone* GetInstance(bool bDetailedInstuction = true, ICapstoneFactory* factory = nullptr)
		{
			return mConcurrentProvider.GetInstance(bDetailedInstuction, factory);
		}
	};
}