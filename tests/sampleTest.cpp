#include <OH/OffsetHunter.h>

int main()
{
	OffsetHunter oh;

	oh.setConfigPath("../../../../samples/DummyLib/dummyConfig.json");

	if (oh.Init() == false)
		return 1;

	oh.Run();

	return 0;
}