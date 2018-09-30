/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/

	Modified: b0yd@securifera.com
	          Removed unnecessary code and added parameters to return lsadump data structures
*/
#pragma once
#include "globals.h"

typedef CONST char *PCSZ;
typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;
typedef PSTRING PCANSI_STRING;

typedef STRING OEM_STRING;
typedef PSTRING POEM_STRING;
typedef CONST STRING* PCOEM_STRING;
typedef CONST UNICODE_STRING *PCUNICODE_STRING;

#define DECLARE_UNICODE_STRING(_var, _string) \
const WCHAR _var ## _buffer[] = _string; \
UNICODE_STRING _var = { sizeof(_string) - sizeof(WCHAR), sizeof(_string), (PWCH) _var ## _buffer }

#define DECLARE_CONST_UNICODE_STRING(_var, _string) \
const WCHAR _var ## _buffer[] = _string; \
const UNICODE_STRING _var = { sizeof(_string) - sizeof(WCHAR), sizeof(_string), (PWCH) _var ## _buffer }

extern VOID WINAPI RtlInitString(OUT PSTRING DestinationString, IN PCSZ SourceString);
extern VOID WINAPI RtlInitUnicodeString(OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString);

extern NTSTATUS WINAPI RtlAnsiStringToUnicodeString(OUT PUNICODE_STRING DestinationString, IN PCANSI_STRING SourceString, IN BOOLEAN AllocateDestinationString);
extern NTSTATUS WINAPI RtlUnicodeStringToAnsiString(OUT PANSI_STRING DestinationString, IN PCUNICODE_STRING SourceString, IN BOOLEAN AllocateDestinationString);

extern VOID WINAPI RtlUpperString(OUT PSTRING DestinationString, IN const STRING *SourceString);
extern NTSTATUS WINAPI RtlUpcaseUnicodeString(IN OUT PUNICODE_STRING DestinationString, IN PCUNICODE_STRING SourceString, IN BOOLEAN AllocateDestinationString);
extern NTSTATUS WINAPI RtlDowncaseUnicodeString(PUNICODE_STRING DestinationString, IN PCUNICODE_STRING SourceString, IN BOOLEAN AllocateDestinationString);
extern WCHAR WINAPI RtlUpcaseUnicodeChar(IN WCHAR SourceCharacter);
extern NTSTATUS WINAPI RtlUpcaseUnicodeStringToOemString(IN OUT POEM_STRING DestinationString, IN PCUNICODE_STRING SourceString, IN BOOLEAN AllocateDestinationString);

extern BOOLEAN WINAPI RtlEqualString(IN const STRING *String1, IN const STRING *String2, IN BOOLEAN CaseInSensitive);
extern BOOLEAN WINAPI RtlEqualUnicodeString(IN PCUNICODE_STRING String1, IN PCUNICODE_STRING String2, IN BOOLEAN CaseInSensitive);

extern LONG WINAPI RtlCompareUnicodeString(IN PCUNICODE_STRING String1, IN PCUNICODE_STRING String2, IN BOOLEAN CaseInSensitive);
extern LONG WINAPI RtlCompareString(IN const STRING *String1, IN const STRING *String2, IN BOOLEAN CaseInSensitive);

extern VOID WINAPI RtlFreeAnsiString(IN OUT PANSI_STRING AnsiString);
extern VOID WINAPI RtlFreeUnicodeString(IN OUT PUNICODE_STRING UnicodeString);
extern VOID WINAPI RtlFreeOemString(IN OUT POEM_STRING OemString);

extern NTSTATUS WINAPI RtlStringFromGUID(IN LPCGUID Guid, PUNICODE_STRING UnicodeString);
extern NTSTATUS WINAPI RtlGUIDFromString(IN PCUNICODE_STRING GuidString, OUT GUID *Guid);
extern NTSTATUS NTAPI RtlValidateUnicodeString(IN ULONG Flags, IN PCUNICODE_STRING UnicodeString);

extern NTSTATUS WINAPI RtlAppendUnicodeStringToString(IN OUT PUNICODE_STRING Destination, IN PCUNICODE_STRING Source);

extern VOID NTAPI RtlRunDecodeUnicodeString(IN BYTE Hash, IN OUT PUNICODE_STRING String);
extern VOID NTAPI RtlRunEncodeUnicodeString(IN OUT PBYTE Hash, IN OUT PUNICODE_STRING String);

BOOL kull_m_string_suspectUnicodeString(IN PUNICODE_STRING pUnicodeString);
wchar_t * kull_m_string_qad_ansi_to_unicode(const char * ansi);
wchar_t * kull_m_string_qad_ansi_c_to_unicode(const char * ansi, SIZE_T szStr);

void kull_m_string_wprintf_hex(LPCVOID lpData, DWORD cbData, DWORD flags);
void kull_m_string_displayGUID(IN LPCGUID pGuid);
void kull_m_string_displaySID(IN PSID pSid);
PWSTR kull_m_string_getRandomGUID();