#pragma once
#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "globals.h"
#include "kull_m_registry.h"
#include "kull_m_crypto_system.h"
#include "kull_m_crypto.h"
#include "kull_m_samlib.h"
#include "kull_m_rpc_ms-credentialkeys.h"
#include "kull_m_rpc_ms-pac.h"
#include "..\main.h"

#define	SYSKEY_LENGTH	16

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

typedef struct _MSCACHE_ENTRY {
	WORD szUserName;
	WORD szDomainName;
	WORD szEffectiveName;
	WORD szFullName;
	WORD szlogonScript;
	WORD szprofilePath;
	WORD szhomeDirectory;
	WORD szhomeDirectoryDrive;
	DWORD userId;
	DWORD primaryGroupId;
	DWORD groupCount;
	WORD szlogonDomainName;
	WORD unk0;
	FILETIME lastWrite;
	DWORD revision;
	DWORD sidCount;
	DWORD flags;
	DWORD unk1;
	DWORD logonPackage;
	WORD szDnsDomainName;
	WORD szupn;
	BYTE iv[LAZY_IV_SIZE];
	BYTE cksum[MD5_DIGEST_LENGTH];
	BYTE enc_data[ANYSIZE_ARRAY];
} MSCACHE_ENTRY, *PMSCACHE_ENTRY;

typedef struct _MSCACHE_ENTRY_PTR {
	UNICODE_STRING UserName;
	UNICODE_STRING Domain;
	UNICODE_STRING DnsDomainName;
	UNICODE_STRING Upn;
	UNICODE_STRING EffectiveName;
	UNICODE_STRING FullName;

	UNICODE_STRING LogonScript;
	UNICODE_STRING ProfilePath;
	UNICODE_STRING HomeDirectory;
	UNICODE_STRING HomeDirectoryDrive;

	PGROUP_MEMBERSHIP Groups;

	UNICODE_STRING LogonDomainName;

} MSCACHE_ENTRY_PTR, *PMSCACHE_ENTRY_PTR;

typedef struct _MSCACHE_DATA {
	BYTE mshashdata[LM_NTLM_HASH_LENGTH];
	BYTE unkhash[LM_NTLM_HASH_LENGTH];
	DWORD unk0;
	DWORD szSC;
	DWORD unkLength;
	DWORD unk2;
	DWORD unk3;
	DWORD unk4;
	DWORD unk5;
	DWORD unk6;
	DWORD unk7;
	DWORD unk8;
} MSCACHE_DATA, *PMSCACHE_DATA;

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
BOOL kuhl_m_lsadump_getNLKMSecretAndCache(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hPolicyBase, IN HKEY hSecurityBase, PNT6_SYSTEM_KEYS lsaKeysStream, PNT5_SYSTEM_KEY lsaKeyUnique, IN PKUHL_LSADUMP_DCC_CACHE_DATA pCacheData);
void kuhl_m_lsadump_printMsCache(PMSCACHE_ENTRY entry, CHAR version);
BOOL kuhl_m_lsadump_decryptSCCache(PBYTE data, DWORD size, HCRYPTPROV hProv, DWORD keySpec);
void kuhl_m_lsadump_getInfosFromServiceName(IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, IN PCWSTR serviceName);
BOOL kuhl_m_lsadump_decryptSecret(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hSecret, IN LPCWSTR KeyName, IN PNT6_SYSTEM_KEYS lsaKeysStream, IN PNT5_SYSTEM_KEY lsaKeyUnique, IN PVOID * pBufferOut, IN PDWORD pSzBufferOut);
void kuhl_m_lsadump_candidateSecret(DWORD szBytesSecrets, PVOID bufferSecret, PCWSTR prefix, PCWSTR secretName, PSVC_STRUCT svc_struct);
BOOL kuhl_m_lsadump_sec_aes256(PNT6_HARD_SECRET hardSecretBlob, DWORD hardSecretBlobSize, PNT6_SYSTEM_KEYS lsaKeysStream, PBYTE sysKey);

NTSTATUS kuhl_m_lsadump_secrets(PSVC_STRUCT *svc_arr, size_t svc_arr_size, LPCSTR szSystem, LPCSTR szSecurity);

#ifdef __cplusplus
}  /* end of the 'extern "C"' block */
#endif