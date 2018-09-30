/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/

	Modified: b0yd@securifera.com
	          Removed unnecessary code and added parameters to return lsadump data structures
*/
#include "kull_m_string.h"

BOOL kull_m_string_suspectUnicodeString(IN PUNICODE_STRING pUnicodeString)
{
	int unicodeTestFlags = IS_TEXT_UNICODE_STATISTICS;
	return ((pUnicodeString->Length == sizeof(wchar_t)) && IsCharAlphaNumeric(pUnicodeString->Buffer[0])) || IsTextUnicode(pUnicodeString->Buffer, pUnicodeString->Length, &unicodeTestFlags);
}


wchar_t * kull_m_string_qad_ansi_to_unicode(const char * ansi)
{
	wchar_t * buffer = NULL;
	if(ansi)
		buffer = kull_m_string_qad_ansi_c_to_unicode(ansi, strlen(ansi));
	return buffer;
}

wchar_t * kull_m_string_qad_ansi_c_to_unicode(const char * ansi, SIZE_T szStr)
{
	wchar_t * buffer = NULL;
	SIZE_T i;

	if(ansi && szStr)
		if(buffer = (wchar_t *) LocalAlloc(LPTR, (szStr + 1) * sizeof(wchar_t)))
			for(i = 0; i < szStr; i++)
				buffer[i] = ansi[i];
	return buffer;
}


PCWCHAR WPRINTF_TYPES[] =
{
	L"%02x",		// WPRINTF_HEX_SHORT
	L"%02x ",		// WPRINTF_HEX_SPACE
	L"0x%02x, ",	// WPRINTF_HEX_C
	L"\\x%02x",		// WPRINTF_HEX_PYTHON
};

void kull_m_string_wprintf_hex(LPCVOID lpData, DWORD cbData, DWORD flags)
{
	DWORD i, sep = flags >> 16;
	PCWCHAR pType = WPRINTF_TYPES[flags & 0x0000000f];

	if((flags & 0x0000000f) == 2)
		kprintf(L"\nBYTE data[] = {\n\t");

	for(i = 0; i < cbData; i++)
	{
		kprintf(pType, ((LPCBYTE) lpData)[i]);
		if(sep && !((i+1) % sep))
		{
			kprintf(L"\n");
			if((flags & 0x0000000f) == 2)
				kprintf(L"\t");
		}
	}
	if((flags & 0x0000000f) == 2)
		kprintf(L"\n};\n");
}

void kull_m_string_displayGUID(IN LPCGUID pGuid)
{
	UNICODE_STRING uString;
	if(NT_SUCCESS(RtlStringFromGUID(pGuid, &uString)))
	{
		kprintf(L"%wZ", &uString);
		RtlFreeUnicodeString(&uString);
	}
}

void kull_m_string_displaySID(IN PSID pSid)
{
	LPWSTR stringSid;
	if(ConvertSidToStringSid(pSid, &stringSid))
	{
		kprintf(L"%s", stringSid);
		LocalFree(stringSid);
	}
	else PRINT_ERROR_AUTO(L"ConvertSidToStringSid");
}
#ifndef MIMIKATZ_W2000_SUPPORT
PWSTR kull_m_string_getRandomGUID()
{
	UNICODE_STRING uString;
	GUID guid;
	PWSTR buffer = NULL;
	if(NT_SUCCESS(UuidCreate(&guid)))
	{
		if(NT_SUCCESS(RtlStringFromGUID(&guid, &uString)))
		{
			if(buffer = (PWSTR) LocalAlloc(LPTR, uString.MaximumLength))
				RtlCopyMemory(buffer, uString.Buffer, uString.MaximumLength);
			RtlFreeUnicodeString(&uString);
		}
	}
	return buffer;
}
#endif

