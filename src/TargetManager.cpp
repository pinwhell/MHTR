#include <OH/TargetManager.h>
#include <OH/FileHelper.h>
#include <OH/DumpTargetGroup.h>
#include <OH/JsonAccesorClassifier.h>
#include <OH/OffsetHunter.h>

#include <iostream>

TargetManager::TargetManager()
{
	mObfucationManager = std::make_unique<ObfuscationManager>();
	mHppWriter = std::make_unique<HeaderFileManager>();

	mHppWriter->SetTraits(&std::cout);

	mDynamicJsonObjName = "obj"; // By default
	mDynamicOffsetSetterFuncName = "Set"; // By default
}

bool TargetManager::Init()
{
	if (FileHelper::IsValidFilePath(mConfigMgr->mDumpTargetPath, true, true) == false)
		return false;

	if (JsonHelper::File2Json(mConfigMgr->mDumpTargetPath, mDumpTargetsRoot) == false)
	{
		printf("Unable to parse DUmp Targets\n");
		return false;
	}

	if (mConfigMgr->mDumpDynamic)
	{
		if (JsonAccesorClassifier::Classify(mConfigMgr->mDumpJsonLibName, mJsonAccesor) == false)
		{
			printf("\"%s\" Library mistyped or not supported\n", mConfigMgr->mDumpJsonLibName.c_str());
			return false;
		}

		mJsonAccesor->setJsonObjectName(mDynamicJsonObjName);
		AddInclude(mJsonAccesor->getGlobalInclude());
	}

	if (mConfigMgr->mDumpEncrypt)
	{
		mObfucationManager->setPath(mConfigMgr->mObfuscationBookPath);
		mObfucationManager->setParent(this);
		mObfucationManager->setObfInfoMutationEnabled(mConfigMgr->mObfustationBookDoMutate);

		if (mObfucationManager->Init() == false)
			return false;
	}

	if (ReadAllTargets() == false)
		return false;

	if (InitAllTargets() == false)
		return false;

	if (mConfigMgr->mHppOutputPath.empty() == false)
	{
		std::unique_ptr<std::ofstream> mHppOutputFile = std::make_unique<std::ofstream>(mConfigMgr->mHppOutputPath);

		if (mHppOutputFile->is_open() == false)
		{
			printf("Unable to open/create \"%s\"\n", mConfigMgr->mHppOutputPath.c_str());
			return false;
		}

		mHppWriter->SetOwnFStream(mHppOutputFile);
	}

	return true;
}

bool TargetManager::InitAllTargets()
{
	for (const auto& kv : mAllTargets)
	{
		if (kv.second->Init() == false)
			return false;
	}

	return true;
}

void TargetManager::ComputeAll()
{
	for (const auto& kv : mAllTargets)
		kv.second->ComputeAll();
}

bool TargetManager::SaveResults()
{
	if (SaveHpp() == false)
		return false;
	
	if (mConfigMgr->mDumpDynamic)
	{
		if (SaveJson() == false)
			return false;
	}

	mObfucationManager->Export();

	return true;
}

bool TargetManager::SaveJson()
{
	bool bSucess = false;

	for (const auto& kv : mAllTargets)
	{
		bool bCurrentResult = false;

		kv.second->ComputeJsonResult();

		if ((bCurrentResult = kv.second->SaveResultJsonToFile()) == false)
			printf("Unable to save json offsets result for %s\n", kv.second->getMacro().c_str());

		bSucess = bSucess || bCurrentResult;
	}

	return bSucess;
}

bool TargetManager::SaveHppRuntime()
{
	mHppWriter->AppendPragmaOnce();

	WriteHppIncludes();

	mHppWriter->AppendNextLine();


}

bool TargetManager::SaveHppCompileTime()
{
	mHppWriter->AppendPragmaOnce();

	WriteHppIncludes();

	mHppWriter->AppendNextLine();

	mHppWriter->BeginStruct(mConfigMgr->mMainCategory);

	/*Inside the struct*/
	
	mHppWriter->AppendMacroIfDefined("STATIC_OFFS");

	WriteHppStaticDeclsDefs();

	// Generate Declaration-Definition here staticly 

	if (mConfigMgr->mDumpDynamic)
	{
		mHppWriter->AppendMacroElse();
		/*Generate Declaration-only here*/

		WriteHppDynDecls();

		mHppWriter->BeginFunction("void", mDynamicOffsetSetterFuncName, { "const " + mJsonAccesor->getJsonObjFullType() + "& " + mDynamicJsonObjName });

		// Generating Decryption Safeguards
		mHppWriter->AppendLineOfCode("static bool initialized = false;"); mHppWriter->AppendNextLine();
		mHppWriter->AppendLineOfCode("if(initialized) return;"); mHppWriter->AppendNextLine();

		/*Generate Definition-only here*/
		
		WriteHppDynDefs(); 
		mHppWriter->AppendNextLine();

		mHppWriter->AppendLineOfCode("initialized = true;");

		mHppWriter->EndFunction();

	}

	mHppWriter->AppendMacroEndIf();
	/*Outside the struct*/
	
	std::vector<StructDeclarationInfo> decls;

	if (mConfigMgr->mDeclareGlobalDumpObj)
		decls.push_back(StructDeclarationInfo(mConfigMgr->mGlobalDumpObjName, true, true));

	mHppWriter->EndStruct(mConfigMgr->mMainCategory, decls);

	return true;
}

void TargetManager::setConfigManager(ConfigManager* configMgr)
{
	mConfigMgr = configMgr;
}

ConfigManager* TargetManager::getConfigManager()
{
	return mConfigMgr;
}

void TargetManager::RemoveTarget(DumpTargetGroup* target)
{
	if (mAllTargets.find(target) == mAllTargets.end())
		return;

	mAllTargets.erase(target);
}

void TargetManager::AddTarget(std::unique_ptr<DumpTargetGroup>& target)
{
	DumpTargetGroup* pDumpTarget = target.get();

	if (mAllTargets.find(pDumpTarget) != mAllTargets.end())
		return;

	mAllTargets[pDumpTarget] = std::move(target);
}

bool TargetManager::ReadAllTargets()
{
	if (mDumpTargetsRoot.isArray() == false)
	{
		printf("Unexpected Format of the \"%s\"\n", mConfigMgr->mDumpTargetPath.c_str());
		return false;
	}

	for (uint32_t i = 0; i < mDumpTargetsRoot.size(); i++) // All Targets
	{
		JsonValueWrapper curr(mDumpTargetsRoot[i]);

		HandleTargetGroupJson(curr);
	}

	return true;
}

bool TargetManager::HandleTargetGroupJson(const JsonValueWrapper& targetGroupRoot)
{

	if (JSON_ASSERT(targetGroupRoot, "targets") == false)
		return false;

	if (JSON_ASSERT_STR_EMPTY(targetGroupRoot, "macro") == false)
	{
		printf("\"macro\" Not present or empty in \"%s\" Targets config\n", mConfigMgr->mDumpTargetPath.c_str());
		return false;
	}

	std::unique_ptr<DumpTargetGroup> targetGroup = std::make_unique<DumpTargetGroup>();

	targetGroup->setTargetManager(this);
	targetGroup->setDumpTargetDescJson(targetGroupRoot);
	targetGroup->setParent(this);
	targetGroup->setTargetJsonPath(mConfigMgr->mDumpTargetPath);

	AddTarget(targetGroup);

	return true;
}

HeaderFileManager* TargetManager::getHppWriter()
{
	return mHppWriter.get();
}

void TargetManager::setJsonAccesor(std::unique_ptr<IJsonAccesor>&& accesor)
{
	mJsonAccesor = std::move(accesor);
}

IJsonAccesor* TargetManager::getJsonAccesor()
{
	return mJsonAccesor.get();
}

void TargetManager::WriteHppIncludes()
{
	for (const auto& kv : mAllTargets)
		kv.second->ReportHppIncludes();

	for (const std::string& include : mIncludes)
		mHppWriter->AppendGlobalInclude(include);
}

void TargetManager::WriteHppStaticDeclsDefs()
{
	for (const auto& kv : mAllTargets)
		kv.second->WriteHppStaticDeclsDefs();
}

void TargetManager::WriteHppDynDecls()
{
	for (const auto& kv : mAllTargets)
		kv.second->WriteHppDynDecls();
}

void TargetManager::WriteHppDynDefs()
{
	for (const auto& kv : mAllTargets)
		kv.second->WriteHppDynDefs();
}

CapstoneHelperProvider* TargetManager::getCapstoneHelperProvider()
{
	return mParent->getCapstoneHelperProvider();
}

ObfuscationManager* TargetManager::getObfuscationManager()
{
	return mObfucationManager.get();
}

void TargetManager::AddInclude(const std::string& toInclude)
{
	mIncludes.insert(toInclude);
}
