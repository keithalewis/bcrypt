// bcrypt.h - Wrappers for bcrypt library
#pragma once
#include <Windows.h>
#include <bcrypt.h>

namespace win {

	namespace BCrypt {

		class OpenAlgorithmProvider {
			BCRYPT_ALG_HANDLE hAlgorithm;
			DWORD cbKeyObject;
			DWORD cbData;
		public:
			OpenAlgorithmProvider(LPCWSTR pszAlgid = BCRYPT_AES_ALGORITHM, LPCWSTR pszImplementation = NULL, ULONG dwFlags = 0)
			{
				NTSTATUS status;

				status = BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgid, pszImplementation, dwFlags);
				//!! check status
				status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, 
					(PBYTE)&cbKeyObject, sizeof(DWORD), &cbData, 0);
			}
		};
	}

}