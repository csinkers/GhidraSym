// Adds Ghidra symbols as WinDbg synthetic symbols
//
// Adapted from https://gist.github.com/ikonst/ebae548dac7934dc0bdf
// Original code by 'blabb'.
// 
// See:
// http://www.woodmann.com/forum/entry.php?262-addsym-windbg-extension-%28extension-to-load-names-from-ida-to-windbg%29
// http://reverseengineering.stackexchange.com/questions/3850/importing-list-of-functions-and-addresses-into-windbg

#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <tchar.h>
#include "engexpcpp.hpp"

EXT_API_VERSION g_ExtApiVersion = { 5 , 5 , EXT_API_VERSION_NUMBER , 0 };
LPEXT_API_VERSION WDBGAPI ExtensionApiVersion() { return &g_ExtApiVersion; }

VOID WDBGAPI WinDbgExtensionDllInit(PWINDBG_EXTENSION_APIS lpExtensionApis, USHORT usMajorVersion, USHORT usMinorVersion)
{
     ExtensionApis = *lpExtensionApis;
}

class EXT_CLASS : public ExtExtension
{
public:
	EXT_CLASS() {}
	EXT_COMMAND_METHOD(addsym);
};

EXT_DECLARE_GLOBALS();


// takes two arguments first is an expression second is a string (path of symbol file)
// !addsym modulename filename 
// e.g. !addsym SomeModuleName C:\tmp\something.exe.xml
// e.g. !addsym 00400000 C:\tmp\something.exe.xml

enum SymbolType
{
	Function,
	Data
};

struct SymbolDef
{
	SymbolType type;
	std::string name;
	uint64_t offset;
	uint32_t size;
};

bool has_prefix(const char **start, const char* prefix)
{
	if (start == nullptr || *start == nullptr)
		return false;

	const char* s = *start;
	for (; *s != 0 && (*s == ' ' || *s == '\t'); s++) {} // Skip whitespace
	for (; *s != 0 && *prefix != 0 && *s == *prefix; s++, prefix++) {} // Skip prefix
	if (*prefix) // Prefix didn't match
		return false;

	*start = s; // Update start pointer if prefix was found
	return true;
}

bool skip_to(const char **start, const char *prefix)
{
	const char* s = *start;
	const char* p = prefix;
	for (; *s != 0 && *p != 0; s++)
	{
		if (*s != *p) p = prefix; // Ignore everything until we match all of prefix
		if (*s == *p) p++;
	}

	*start = s; // Update start pointer
	return *p == 0;
}

void parse_line(const char* line, std::map<uint64_t, SymbolDef>& symbols, uint64_t &module_offset)
{
    // Quick and dirty parsing.
	static bool in_functions = false;
	static bool in_data = false;
	static bool in_symbols = false;
	const char* s = line;

	if (module_offset == 0 && has_prefix(&s, "<PROGRAM NAME=\""))
	{
		// <PROGRAM NAME="test.exe" EXE_PATH="C:/Tmp/ReversingTest/test.exe" EXE_FORMAT="Portable Executable (PE)" IMAGE_BASE="00400000">
        if (skip_to(&s, "IMAGE_BASE=\""))
            module_offset = strtoull(s, nullptr, 16);
    }
    else if (has_prefix(&s, "<FUNCTIONS"))    { in_functions = *s != '/'; }
    else if (has_prefix(&s, "<DATA"))         { in_data = *s != '/'; }
    else if (has_prefix(&s, "<SYMBOL_TABLE")) { in_symbols = *s != '/'; }
	else if (in_functions && has_prefix(&s, "</FUNCTIONS>"))  { in_functions = false;}
	else if (in_data && has_prefix(&s, "</DATA>"))            { in_data = false;}
	else if (in_symbols && has_prefix(&s, "</SYMBOL_TABLE>")) { in_symbols = false;}
	else if (in_functions && has_prefix(&s, "<FUNCTION ENTRY_POINT=\""))
	{
        /*
        <FUNCTION ENTRY_POINT="00401005" NAME="gets_s" LIBRARY_FUNCTION="n">
            <ADDRESS_RANGE START="00401005" END="00401009" />
            <TYPEINFO_CMT>undefined __cdecl gets_s(char * buffer)</TYPEINFO_CMT>
            <STACK_FRAME LOCAL_VAR_SIZE="0xc8" PARAM_OFFSET="0x4" RETURN_ADDR_SIZE="0x0" BYTES_PURGED="0">
                <STACK_VAR STACK_PTR_OFFSET="-0xc4" NAME="local_c4" DATATYPE="undefined1" DATATYPE_NAMESPACE="/" SIZE="0x1" />
                <STACK_VAR STACK_PTR_OFFSET="0x4" NAME="buffer" DATATYPE="char *" DATATYPE_NAMESPACE="/" SIZE="0x4" />
            </STACK_FRAME>
        </FUNCTION>
        */
		const uint64_t offset = strtoull(s, nullptr, 16) - module_offset;

		if (skip_to(&s, "\" NAME=\""))
		{
			std::stringstream os;
			for (; *s != 0 && *s != '"'; s++)
				os << *s;

			symbols[offset] = { Function, os.str(), offset, 4 };
		}
	}
	else if (in_functions && has_prefix(&s, "<ADDRESS_RANGE START=\""))
	{
		const uint64_t start_offset = strtoull(s, nullptr, 16);
		if (skip_to(&s, "\" END=\""))
		{
			const uint64_t end_offset = strtoull(s, nullptr, 16);
			const auto it = symbols.find(start_offset - module_offset);
			if (it != symbols.end())
				it->second.size = (uint32_t)(end_offset - start_offset);
		}
	}
	else if (in_data && has_prefix(&s, "<DEFINED_DATA ADDRESS=\""))
	{
		/*
		<DATA>
			<DEFINED_DATA ADDRESS="004fee68" DATATYPE="string" DATATYPE_NAMESPACE="/" SIZE="0x18" />
		</DATA>
		 */
		const uint64_t offset = strtoull(s, nullptr, 16) - module_offset;

		if (skip_to(&s, "\" SIZE=\"0x"))
		{
			const uint32_t size = strtoul(s, nullptr, 16);
			symbols[offset] = { Data, std::string(), offset, size };
		}
	}
	else if (in_symbols && has_prefix(&s, "<SYMBOL ADDRESS=\""))
	{
		/*
		<SYMBOL_TABLE>
			<SYMBOL ADDRESS="00546fe4" NAME="g_UiPool" NAMESPACE="" TYPE="global" SOURCE_TYPE="USER_DEFINED" PRIMARY="y" />
		</SYMBOL_TABLE>
		 */

		// Assume symbols come after defined_data, only fix up data symbols that don't have a name
		const uint64_t offset = strtoull(s, nullptr, 16) - module_offset;
		const auto it = symbols.find(offset);

		if (it != symbols.end() && skip_to(&s, " NAME=\""))
		{
			std::stringstream os;
			for (; *s != 0 && *s != '"'; s++)
				os << *s;

			if (skip_to(&s, " NAMESPACE=\"\"") && skip_to(&s, " TYPE=\"global\"") && skip_to(&s, " PRIMARY=\"y\""))
				it->second.name = os.str();
		}
	}
}

EXT_COMMAND(
	addsym,
	"windbg extension to use names that are generated by ghidra \n do .reload /f MODULE.ext=base,size prior to using this extension",
	"{;e;MODULE;An expression or address like nt / 0x804d7000 }{;x;path;path to ghidra XML export file c:\\tmp\\MODULE.EXE.xml}"
)
{
	std::ifstream fs;
	std::string inbuff, buff;
	const ULONG64 imagebase = GetUnnamedArgU64(0);

	const auto path = GetUnnamedArgStr(1);
	if (path == nullptr)
	{
		Out("Expected xml filename as second parameter\n");
		return;
	}

	fs.open(path);

	if ((fs.rdstate() & std::ifstream::failbit) != 0)
	{
		Out("failed to open file \"%s\"\n", path);
		return;
	}

	std::map<uint64_t, SymbolDef> symbols;

	{
		Out("Parsing symbols");
		uint64_t offset = 0;
		int i = 0;
		while (getline(fs, buff))
		{
			if (m_Control3->GetInterrupt() == S_OK) break;
            parse_line(buff.c_str(), symbols, offset);
			if (++i % 500 == 0) Out(".");
		}
		fs.close();

		size_t count = 0;
		for (const auto &it : symbols)
			if (!it.second.name.empty())
				count++;
		Out("\n%d symbols parsed\n", count);
	}

	{
		Out("Registering symbols");
		int i = 0;
		for (auto &it : symbols)
		{
			auto &symbol = it.second;
			if (!symbol.name.empty())
			{
				m_Symbols3->AddSyntheticSymbol(
					imagebase + symbol.offset,
					symbol.size,
					symbol.name.c_str(),
					DEBUG_ADDSYNTHSYM_DEFAULT,
					nullptr);

				if (++i % 500 == 0) Out(".");
			}
		}
		Out("\nSymbols registered\n", i);
	}
}

