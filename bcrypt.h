// bcrypt.h - Wrappers for bcrypt library
#pragma once
#include <Windows.h>
#include <bcrypt.h>
#include <iterator>
#include <stdexcept>
#include <string>

#pragma comment(lib, "Bcrypt.lib")

namespace win::BCrypt {

	// Buffer for holding bcrypt objects.
	using Buffer = std::basic_string<UCHAR>;

	// Spans???

	class Algorithm {
		BCRYPT_ALG_HANDLE hAlgorithm;
		DWORD cbKeyObject;
		DWORD cbData;
		PBYTE pbKeyObject;
		DWORD cbBlockLen;

	public:
		Algorithm()
			: hAlgorithm(NULL)
		{ }
		Algorithm(const Algorithm&) = delete;
		Algorithm& operator=(const Algorithm&) = delete;
		~Algorithm()
		{
			if (hAlgorithm) {
				BCryptCloseAlgorithmProvider(hAlgorithm, 0);
			}
		}
		operator BCRYPT_ALG_HANDLE& ()
		{
			return hAlgorithm;
		}

		// https://docs.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers
		using Provider = const LPCWSTR;

		inline static Provider RSA = BCRYPT_RSA_ALGORITHM;
		inline static Provider RSA_SIGN = BCRYPT_RSA_SIGN_ALGORITHM;
		inline static Provider DH = BCRYPT_DH_ALGORITHM;
		inline static Provider DSA = BCRYPT_DSA_ALGORITHM;
		inline static Provider RC2 = BCRYPT_RC2_ALGORITHM;
		inline static Provider RC4 = BCRYPT_RC4_ALGORITHM;
		inline static Provider AES = BCRYPT_AES_ALGORITHM;
		inline static Provider DES = BCRYPT_DES_ALGORITHM;
		inline static Provider DESX = BCRYPT_DESX_ALGORITHM;
		inline static Provider _3DES = BCRYPT_3DES_ALGORITHM;
		inline static Provider _3DES_112 = BCRYPT_3DES_112_ALGORITHM;
		inline static Provider MD2 = BCRYPT_MD2_ALGORITHM;
		inline static Provider MD4 = BCRYPT_MD4_ALGORITHM;
		inline static Provider MD5 = BCRYPT_MD5_ALGORITHM;
		inline static Provider SHA1 = BCRYPT_SHA1_ALGORITHM;
		inline static Provider SHA256 = BCRYPT_SHA256_ALGORITHM;
		inline static Provider SHA384 = BCRYPT_SHA384_ALGORITHM;
		inline static Provider SHA512 = BCRYPT_SHA512_ALGORITHM;
		inline static Provider AES_GMAC = BCRYPT_AES_GMAC_ALGORITHM;
		inline static Provider AES_CMAC = BCRYPT_AES_CMAC_ALGORITHM;
		inline static Provider ECDSA_P256 = BCRYPT_ECDSA_P256_ALGORITHM;
		inline static Provider ECDSA_P384 = BCRYPT_ECDSA_P384_ALGORITHM;
		inline static Provider ECDSA_P521 = BCRYPT_ECDSA_P521_ALGORITHM;
		inline static Provider ECDH_P256 = BCRYPT_ECDH_P256_ALGORITHM;
		inline static Provider ECDH_P384 = BCRYPT_ECDH_P384_ALGORITHM;
		inline static Provider ECDH_P521 = BCRYPT_ECDH_P521_ALGORITHM;
		inline static Provider RNG = BCRYPT_RNG_ALGORITHM;
		inline static Provider FIPS186DSARNG = BCRYPT_RNG_FIPS186_DSA_ALGORITHM;
		inline static Provider DUALECRNG = BCRYPT_RNG_DUAL_EC_ALGORITHM;
		inline static Provider SP800_108_CTR_HMAC = BCRYPT_SP800108_CTR_HMAC_ALGORITHM;
		inline static Provider SP800_56A_CONCAT = BCRYPT_SP80056A_CONCAT_ALGORITHM;
		inline static Provider PBKDF2 = BCRYPT_PBKDF2_ALGORITHM;
		inline static Provider CAPI_KDF = BCRYPT_CAPI_KDF_ALGORITHM;
		inline static Provider TLS1_1_KDF = BCRYPT_TLS1_1_KDF_ALGORITHM;
		inline static Provider TLS1_2_KDF = BCRYPT_TLS1_2_KDF_ALGORITHM;
		inline static Provider ECDSA = BCRYPT_ECDSA_ALGORITHM;
		inline static Provider ECDH = BCRYPT_ECDH_ALGORITHM;
		inline static Provider XTS_AES = BCRYPT_XTS_AES_ALGORITHM;
		inline static Provider HKDF = BCRYPT_HKDF_ALGORITHM;

		NTSTATUS OpenProvider(Provider pszAlgid = AES, LPCWSTR pszImplementation = NULL, ULONG dwFlags = 0)
		{
			return BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgid, pszImplementation, dwFlags);
		}

		NTSTATUS GetProperty(LPCWSTR pszProperty, DWORD& dword) 
		{
			DWORD data;

			return BCryptGetProperty(hAlgorithm, pszProperty, (PBYTE)&dword, sizeof(DWORD), &data, 0);
		}
		NTSTATUS SetProperty(LPCWSTR pszProperty, Buffer& input)
		{
			return BCryptSetProperty(hAlgorithm, pszProperty, input.data(), input.size(), 0);
		}

	};

	class Key {
		Algorithm& hAlg;
		BCRYPT_KEY_HANDLE hKey;
	public:
		Key(Algorithm& hAlg)
			: hAlg(hAlg), hKey(NULL)
		{ }
		Key(const Key&) = delete;
		Key& operator=(const Key&) = delete;
		~Key()
		{
			if (hKey) {
				BCryptDestroyKey(hKey);
			}
		}
		operator BCRYPT_KEY_HANDLE& ()
		{
			return hKey;
		}
		NTSTATUS GenerateSymmetric(Buffer& keyObject, Buffer& secret)
		{
			return BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject.data(), keyObject.size(), secret.data(), secret.size(), 0);
		}
		Buffer Encrypt(Buffer& input, PUCHAR pbIV)
		{
			Buffer result;
			NTSTATUS status;
			ULONG cbResult, cbBlockLen;

			status = hAlg.GetProperty(BCRYPT_BLOCK_LENGTH, cbBlockLen);

			status = BCryptEncrypt(hKey, input.data(), input.size(), NULL, pbIV, cbBlockLen, NULL, 0, &cbResult, BCRYPT_BLOCK_PADDING);
			result.resize(cbResult);
			
			status = BCryptEncrypt(hKey, input.data(), input.size(), NULL, pbIV, cbBlockLen, result.data(), result.size(), &cbResult, BCRYPT_BLOCK_PADDING);
			status = status;

			return result;
		}
	};

}