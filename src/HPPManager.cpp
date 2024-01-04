#include <OH/HPPManager.h>
#include <OH/StringHelper.h>

HeaderFileManager::HeaderFileManager()
	: m_TabLevel(0x0)
{

}

void HeaderFileManager::AppendPragmaOnce()
{
	std::ostream& traits = *m_Traits;

	traits << "#pragma once" << std::endl << std::endl;
}

void HeaderFileManager::AppendMacroIf()
{
	std::ostream& traits = *m_Traits;

	traits << "#if";
}

void HeaderFileManager::AppendMacroEndIf()
{
	std::ostream& traits = *m_Traits;

	traits << "#endif" << std::endl << std::endl;
}

void HeaderFileManager::AppendMacroElse()
{
	std::ostream& traits = *m_Traits;

	traits << "#else" << std::endl << std::endl;
}


void HeaderFileManager::AppendMacroDefined(const std::string& macroName)
{
	std::ostream& traits = *m_Traits;

	traits << "defined(" << macroName << ")";
}

void HeaderFileManager::AppendString(const std::string& str)
{
	std::ostream& traits = *m_Traits;

	traits << str;
}

void HeaderFileManager::AppendMacroIfDefined(const std::string& macroName, bool bTerminateLine)
{
	AppendMacroIf(); AppendString(" "); AppendMacroDefined(macroName); if (bTerminateLine) AppendNextLine();
}

void HeaderFileManager::AppendTab()
{
	std::ostream& traits = *m_Traits;

	traits << "\t";
}

void HeaderFileManager::AppendTab(uintptr_t count)
{
	for (size_t i = 0; i < count; i++)
		AppendTab();
}

void HeaderFileManager::AppendConstUintVar(const std::string& name, bool bApplyTabs, bool bApplyVal, uintptr_t val, bool bJumpNewLine)
{
	std::ostream& traits = *m_Traits;

	AppendTab(m_TabLevel); AppendConstExpr(false); AppendString(" "); AppendUintVar(name, false, bApplyVal, val, bJumpNewLine);
}

void HeaderFileManager::AppendComment(const std::string& comment, bool bJumpNewLine)
{
	AppendString(" // " + StringHelper::Unify(StringHelper::Tokenize(comment, '\n'))); if (bJumpNewLine) AppendNextLine();
}

void HeaderFileManager::AppendNextLine()
{
	std::ostream& traits = *m_Traits;

	traits << std::endl;
}

void HeaderFileManager::AppendGlobalInclude(const std::string& fileName)
{
	std::ostream& traits = *m_Traits;

	traits << "#include <" << fileName << ">\n";
}

void HeaderFileManager::BeginNameSpace(const std::string& name)
{
	std::ostream& traits = *m_Traits;

	AppendTab(m_TabLevel); traits << "namespace " << name << " {" << std::endl; m_TabLevel++;
	//AppendNextLine();

}

void HeaderFileManager::BeginStruct(const std::string& name)
{
	std::ostream& traits = *m_Traits;

	AppendTab(m_TabLevel); traits << "struct " << name << " {"; AppendNextLine(); m_TabLevel++;
}

void HeaderFileManager::EndStruct(const std::string& structName, const std::vector<StructDeclarationInfo>& structDecls)
{
	std::ostream& traits = *m_Traits;

	//AppendNextLine();
	m_TabLevel--; AppendTab(m_TabLevel);  traits << "} ";

	std::vector<const StructDeclarationInfo*> DeclsExterns;

	for (size_t i = 0; i < structDecls.size(); i++)
	{
		const StructDeclarationInfo& currDeclInf = structDecls[i];

		if (!currDeclInf.bExtern)
		{
			if (i != 0)
				AppendString(", ");

			if (currDeclInf.bExtern) AppendString("extern ");
			if (currDeclInf.bPointer) AppendString("*");
			AppendString(currDeclInf.name);
		}
		else DeclsExterns.push_back(&currDeclInf);
	}

	AppendString(";"); AppendNextLine();

	for (const auto* currExternDecl : DeclsExterns)
	{
		AppendString("extern ");
		AppendString(structName + " ");
		if (currExternDecl->bPointer) AppendString("*");
		AppendString(currExternDecl->name);
		AppendString(";");
		AppendNextLine();
	}
}

void HeaderFileManager::EndNameSpace(const std::string& name)
{
	std::ostream& traits = *m_Traits; 

	//AppendNextLine();
	m_TabLevel--; AppendTab(m_TabLevel);  traits << "} "; if (!name.empty()) AppendComment(name + " Namespace Ending");
}

void HeaderFileManager::AppendConstExpr(bool bNewLine)
{
	std::ostream& traits = *m_Traits;

	traits << "constexpr"; if (bNewLine) AppendNextLine();
}

void HeaderFileManager::AppendUintVar(const std::string& varName, bool bApplyTabs, bool bApplyVal, uintptr_t val, bool bNewLine)
{
	std::ostream& traits = *m_Traits;

	if (bApplyTabs) AppendTab(m_TabLevel);	traits << "uintptr_t " << varName; if (bApplyVal) { traits << " = 0x" << std::hex << val; } traits << ";";  if (bNewLine) AppendNextLine();
}


void HeaderFileManager::SetTraits(std::ostream* newTrait)
{
	m_Traits = newTrait;
	Reset();
}

void HeaderFileManager::BeginFunction(const std::string& retType, const std::string& functionName, const std::vector<std::string>& params)
{
	std::ostream& traits = *m_Traits;

	AppendTab(m_TabLevel);
	traits << retType << " " << functionName << "(";
	for (size_t i = 0; i < params.size(); i++)
	{
		if (i != 0) traits << ", ";

		traits << params[i];
	}; 
	traits << ") {"; AppendNextLine();
}

void HeaderFileManager::EndFunction()
{
	std::ostream& traits = *m_Traits;

	AppendTab(m_TabLevel);  traits << "}"; AppendNextLine();
}

void HeaderFileManager::AppendLineOfCode(const std::string& loc, bool bApplyTabs, bool bNewLine)
{
	std::ostream& traits = *m_Traits;

	if(bApplyTabs) AppendTab(m_TabLevel);
	traits << loc;
	if(bNewLine) AppendNextLine();
}

void HeaderFileManager::Reset()
{
	m_TabLevel = 0x0;
}

void HeaderFileManager::SetOwnFStream(std::unique_ptr<std::ofstream>& fStream)
{
	m_FTraits = std::move(fStream);
	SetTraits(m_FTraits.get());
}

