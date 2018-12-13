/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/

	Modified: b0yd@securifera.com
	          Removed unnecessary code and added parameters to return lsadump data structures
*/

#pragma once
#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "globals.h"
#include "kull_m_registry.h"
#include "kull_m_crypto_system.h"
#include "kull_m_crypto.h"
#include "..\main.h"

#define	SYSKEY_LENGTH	16
#define	LM_NTLM_HASH_LENGTH	16

//NTSTATUS kuhl_m_lsadump_secrets(int argc, wchar_t * argv[], BOOL secretsOrCache);

typedef struct _POL_REVISION {
	USHORT Minor;
	USHORT Major;
} POL_REVISION, *PPOL_REVISION;

typedef struct _NT6_CLEAR_SECRET {
	DWORD SecretSize;
	DWORD unk0;
	DWORD unk1;
	DWORD unk2;
	BYTE  Secret[ANYSIZE_ARRAY];
} NT6_CLEAR_SECRET, *PNT6_CLEAR_SECRET;

#define LAZY_NT6_IV_SIZE	32
typedef struct _NT6_HARD_SECRET {
	DWORD version;
	GUID KeyId;
	DWORD algorithm;
	DWORD flag;
	BYTE lazyiv[LAZY_NT6_IV_SIZE];
	union {
		NT6_CLEAR_SECRET clearSecret;
		BYTE encryptedSecret[ANYSIZE_ARRAY];
	};
} NT6_HARD_SECRET, *PNT6_HARD_SECRET;

typedef struct _KUHL_LSADUMP_DCC_CACHE_DATA {
	LPCWSTR username;
	BYTE ntlm[LM_NTLM_HASH_LENGTH];
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hProv;
	DWORD keySpec;
} KUHL_LSADUMP_DCC_CACHE_DATA, *PKUHL_LSADUMP_DCC_CACHE_DATA;

typedef struct _NT6_SYSTEM_KEY {
	GUID KeyId;
	DWORD KeyType;
	DWORD KeySize;
	BYTE Key[ANYSIZE_ARRAY];
} NT6_SYSTEM_KEY, *PNT6_SYSTEM_KEY;

typedef struct _NT6_SYSTEM_KEYS {
	DWORD unkType0;
	GUID CurrentKeyID;
	DWORD unkType1;
	DWORD nbKeys;
	NT6_SYSTEM_KEY Keys[ANYSIZE_ARRAY];
} NT6_SYSTEM_KEYS, *PNT6_SYSTEM_KEYS;

typedef struct _NT5_SYSTEM_KEY {
	BYTE key[16];
} NT5_SYSTEM_KEY, *PNT5_SYSTEM_KEY;

#define LAZY_IV_SIZE	16
typedef struct _NT5_SYSTEM_KEYS {
	DWORD unk0;
	DWORD unk1;
	DWORD unk2;
	NT5_SYSTEM_KEY keys[3];
	BYTE lazyiv[LAZY_IV_SIZE];
} NT5_SYSTEM_KEYS, *PNT5_SYSTEM_KEYS;

typedef struct _NT5_HARD_SECRET {
	DWORD encryptedStructSize;
	DWORD unk0;
	DWORD unk1; // it's a trap, it's PTR !
	BYTE encryptedSecret[ANYSIZE_ARRAY];
} NT5_HARD_SECRET, *PNT5_HARD_SECRET;

typedef struct _KIWI_ENC_SC_DATA {
	BYTE toSign[32];
	BYTE toHash[32];
	BYTE toDecrypt[ANYSIZE_ARRAY];
} KIWI_ENC_SC_DATA, *PKIWI_ENC_SC_DATA;

typedef struct _KIWI_ENC_SC_DATA_NEW {
	BYTE Header[8]; // SuppData
	DWORD unk0;
	DWORD unk1;
	DWORD unk2;
	DWORD dataSize;
	KIWI_ENC_SC_DATA data;
} KIWI_ENC_SC_DATA_NEW, *PKIWI_ENC_SC_DATA_NEW;

typedef struct _NTLM_SUPPLEMENTAL_CREDENTIAL_V4 {
	ULONG Version;
	ULONG Flags;
	ULONG unk;
	UCHAR NtPassword[LM_NTLM_HASH_LENGTH];
} NTLM_SUPPLEMENTAL_CREDENTIAL_V4, *PNTLM_SUPPLEMENTAL_CREDENTIAL_V4;

BOOL kuhl_m_lsadump_getComputerAndSyskey(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hSystemBase, OUT LPBYTE sysKey);
BOOL kuhl_m_lsadump_getLsaKeyAndSecrets(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hSecurityBase, IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, IN LPBYTE sysKey, IN BOOL secretsOrCache, IN PKUHL_LSADUMP_DCC_CACHE_DATA pCacheData, PSVC_STRUCT *svc_arr, IN size_t svc_arr_size );
BOOL kuhl_m_lsadump_getSecrets(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hPolicyBase, IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, PNT6_SYSTEM_KEYS lsaKeysStream, PNT5_SYSTEM_KEY lsaKeyUnique, PSVC_STRUCT *svc_arr, IN size_t svc_arr_size);
void kuhl_m_lsadump_getInfosFromServiceName(IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, IN PCWSTR serviceName);
BOOL kuhl_m_lsadump_decryptSecret(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hSecret, IN LPCWSTR KeyName, IN PNT6_SYSTEM_KEYS lsaKeysStream, IN PNT5_SYSTEM_KEY lsaKeyUnique, IN PVOID * pBufferOut, IN PDWORD pSzBufferOut);
void kuhl_m_lsadump_candidateSecret(DWORD szBytesSecrets, PVOID bufferSecret, PCWSTR prefix, PCWSTR secretName, PSVC_STRUCT svc_struct);
BOOL kuhl_m_lsadump_sec_aes256(PNT6_HARD_SECRET hardSecretBlob, DWORD hardSecretBlobSize, PNT6_SYSTEM_KEYS lsaKeysStream, PBYTE sysKey);

NTSTATUS kuhl_m_lsadump_secrets(HKEY passedKey, PSVC_STRUCT *svc_arr, size_t svc_arr_size );

#ifdef __cplusplus
}  /* end of the 'extern "C"' block */
#endif