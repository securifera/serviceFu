/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/

	Modified: b0yd@securifera.com
	          Removed unnecessary code and added parameters to return lsadump data structures
*/
#pragma once
#include "globals.h"
#include "kull_m_string.h"
#include "kull_m_crypto_system.h"

#define CALG_CRC32	(ALG_CLASS_HASH | ALG_TYPE_ANY | 0)

#define AES_256_KEY_SIZE	(256/8)
#define AES_128_KEY_SIZE	(128/8)
#define AES_BLOCK_SIZE		16

typedef struct _GENERICKEY_BLOB {
	BLOBHEADER Header;
	DWORD dwKeyLen;
} GENERICKEY_BLOB, *PGENERICKEY_BLOB;

typedef struct _RSA_GENERICKEY_BLOB {
	BLOBHEADER Header;
	RSAPUBKEY RsaKey; // works with RSA2 ;)
} RSA_GENERICKEY_BLOB, *PRSA_GENERICKEY_BLOB;

#ifndef IPSEC_FLAG_CHECK
#define IPSEC_FLAG_CHECK 0xf42a19b6
#endif

#ifndef CNG_RSA_PRIVATE_KEY_BLOB
#define CNG_RSA_PRIVATE_KEY_BLOB (LPCSTR) 83
#endif


BOOL kull_m_crypto_hash(ALG_ID algid, LPCVOID data, DWORD dataLen, LPVOID hash, DWORD hashWanted);
BOOL kull_m_crypto_hkey(HCRYPTPROV hProv, ALG_ID calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY *hKey, HCRYPTPROV *hSessionProv);
BOOL kull_m_crypto_close_hprov_delete_container(HCRYPTPROV hProv);
BOOL kull_m_crypto_hkey_session(ALG_ID calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY *hSessionKey, HCRYPTPROV *hSessionProv);
