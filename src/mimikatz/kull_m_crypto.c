/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/

	Modified: b0yd@securifera.com
	          Removed unnecessary code and added parameters to return lsadump data structures
*/
#include "kull_m_crypto.h"

#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)    // ntsubauth

BOOL kull_m_crypto_hash(ALG_ID algid, LPCVOID data, DWORD dataLen, LPVOID hash, DWORD hashWanted)
{
	BOOL status = FALSE;
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	DWORD hashLen;
	PBYTE buffer;
	PKERB_CHECKSUM pCheckSum;
	PVOID Context;

	if(algid == CALG_CRC32)
	{
		if((hashWanted == sizeof(DWORD)) && NT_SUCCESS(CDLocateCheckSum(KERB_CHECKSUM_REAL_CRC32, &pCheckSum)))
		{
			if(NT_SUCCESS(pCheckSum->Initialize(0, &Context)))
			{
				pCheckSum->Sum(Context, dataLen, data);
				status = NT_SUCCESS(pCheckSum->Finalize(Context, hash));
				pCheckSum->Finish(&Context);
			}
		}
	}
	else if(CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		if(CryptCreateHash(hProv, algid, 0, 0, &hHash))
		{
			if(CryptHashData(hHash, (LPCBYTE) data, dataLen, 0))
			{
				if(CryptGetHashParam(hHash, HP_HASHVAL, NULL, &hashLen, 0))
				{
					if(buffer = (PBYTE) LocalAlloc(LPTR, hashLen))
					{
						status = CryptGetHashParam(hHash, HP_HASHVAL, buffer, &hashLen, 0);
						RtlCopyMemory(hash, buffer, min(hashLen, hashWanted));
						LocalFree(buffer);
					}
				}
			}
			CryptDestroyHash(hHash);
		}
		CryptReleaseContext(hProv, 0);
	}
	return status;
}

BOOL kull_m_crypto_hkey(HCRYPTPROV hProv, ALG_ID calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY *hKey, HCRYPTPROV *hSessionProv)
{
	BOOL status = FALSE;
	PGENERICKEY_BLOB keyBlob;
	DWORD szBlob = sizeof(GENERICKEY_BLOB) + keyLen;
	
	if(calgid != CALG_3DES)
	{
		if(keyBlob = (PGENERICKEY_BLOB) LocalAlloc(LPTR, szBlob))
		{
			keyBlob->Header.bType = PLAINTEXTKEYBLOB;
			keyBlob->Header.bVersion = CUR_BLOB_VERSION;
			keyBlob->Header.reserved = 0;
			keyBlob->Header.aiKeyAlg = calgid;
			keyBlob->dwKeyLen = keyLen;
			RtlCopyMemory((PBYTE) keyBlob + sizeof(GENERICKEY_BLOB), key, keyBlob->dwKeyLen);
			status = CryptImportKey(hProv, (LPCBYTE) keyBlob, szBlob, 0, flags, hKey);
			LocalFree(keyBlob);
		}
	}
	else if(hSessionProv)
		status = kull_m_crypto_hkey_session(calgid, key, keyLen, flags, hKey, hSessionProv);
	
	return status;
}

BOOL kull_m_crypto_close_hprov_delete_container(HCRYPTPROV hProv)
{
	BOOL status = FALSE;
	DWORD provtype, szLen = 0;
	PSTR container, provider;
	if(CryptGetProvParam(hProv, PP_CONTAINER, NULL, &szLen, 0))
	{
		if(container = (PSTR) LocalAlloc(LPTR, szLen))
		{
			if(CryptGetProvParam(hProv, PP_CONTAINER, (LPBYTE) container, &szLen, 0))
			{
				if(CryptGetProvParam(hProv, PP_NAME, NULL, &szLen, 0))
				{
					if(provider = (PSTR) LocalAlloc(LPTR, szLen))
					{
						if(CryptGetProvParam(hProv, PP_NAME, (LPBYTE) provider, &szLen, 0))
						{
							szLen = sizeof(DWORD);
							if(CryptGetProvParam(hProv, PP_PROVTYPE, (LPBYTE) &provtype, &szLen, 0))
							{
								CryptReleaseContext(hProv, 0);
								status = CryptAcquireContextA(&hProv, container, provider, provtype, CRYPT_DELETEKEYSET);
							}
						}
						LocalFree(provider);
					}
				}
				LocalFree(container);
			}
		}
	}
	if(!status)
		PRINT_ERROR_AUTO(L"CryptGetProvParam/CryptAcquireContextA");
	return status;
}

BOOL kull_m_crypto_hkey_session(ALG_ID calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY *hSessionKey, HCRYPTPROV *hSessionProv)
{
	BOOL status = FALSE;
	PBYTE keyblob, pbSessionBlob, ptr;
	DWORD dwkeyblob, dwLen, i;
	PWSTR container;
	HCRYPTKEY hPrivateKey;

	if(container = kull_m_string_getRandomGUID())
	{
		if(CryptAcquireContext(hSessionProv, container, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET))
		{
			hPrivateKey = 0;
			if(CryptGenKey(*hSessionProv, AT_KEYEXCHANGE, CRYPT_EXPORTABLE | RSA1024BIT_KEY, &hPrivateKey)) // 1024
			{
				if(CryptExportKey(hPrivateKey, 0, PRIVATEKEYBLOB, 0, NULL, &dwkeyblob))
				{
					if(keyblob = (LPBYTE)LocalAlloc(LPTR, dwkeyblob))
					{
						if(CryptExportKey(hPrivateKey, 0, PRIVATEKEYBLOB, 0, keyblob, &dwkeyblob))
						{
							CryptDestroyKey(hPrivateKey);
							hPrivateKey = 0;

							dwLen = ((RSAPUBKEY *) (keyblob + sizeof(PUBLICKEYSTRUC)))->bitlen / 8;
							((RSAPUBKEY *) (keyblob + sizeof(PUBLICKEYSTRUC)))->pubexp = 1;
							ptr = keyblob + sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY);

							ptr += 2 * dwLen; // Skip pubexp, modulus, prime1, prime2
							*ptr = 1; // Convert exponent1 to 1
							RtlZeroMemory(ptr + 1, dwLen / 2 - 1);
							ptr += dwLen / 2; // Skip exponent1
							*ptr = 1; // Convert exponent2 to 1
							RtlZeroMemory(ptr + 1, dwLen / 2 - 1);
							ptr += dwLen; // Skip exponent2, coefficient
							*ptr = 1; // Convert privateExponent to 1
							RtlZeroMemory(ptr + 1, (dwLen/2) - 1);

							if(CryptImportKey(*hSessionProv, keyblob, dwkeyblob, 0, 0, &hPrivateKey))
							{
								dwkeyblob = (1024 / 8) + sizeof(ALG_ID) + sizeof(BLOBHEADER); // 1024
								if(pbSessionBlob = (LPBYTE)LocalAlloc(LPTR, dwkeyblob))
								{
									((BLOBHEADER *) pbSessionBlob)->bType = SIMPLEBLOB;
									((BLOBHEADER *) pbSessionBlob)->bVersion = CUR_BLOB_VERSION;
									((BLOBHEADER *) pbSessionBlob)->reserved = 0;
									((BLOBHEADER *) pbSessionBlob)->aiKeyAlg = calgid;
									ptr = pbSessionBlob + sizeof(BLOBHEADER);
									*(ALG_ID *) ptr = CALG_RSA_KEYX;
									ptr += sizeof(ALG_ID);

									for (i = 0; i < keyLen; i++)
										ptr[i] = ((LPCBYTE) key)[keyLen - i - 1];
									ptr += (keyLen + 1);
									for (i = 0; i < dwkeyblob - (sizeof(ALG_ID) + sizeof(BLOBHEADER) + keyLen + 3); i++)
										if (ptr[i] == 0) ptr[i] = 0x42;
									pbSessionBlob[dwkeyblob - 2] = 2;
									status = CryptImportKey(*hSessionProv, pbSessionBlob, dwkeyblob, hPrivateKey, flags, hSessionKey);
									LocalFree(pbSessionBlob);
								}
							}
						}
						LocalFree(keyblob);
					}
				}
			}
			if(hPrivateKey)
				CryptDestroyKey(hPrivateKey);
			if(!status)
				kull_m_crypto_close_hprov_delete_container(*hSessionProv);
		}
		LocalFree(container);
	}
	return status;
}
