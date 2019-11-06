#include "bcrypt.h"

using namespace win::BCrypt;

static const UCHAR rgbPlaintext[] = "abcdefghijklmnop";
static const UCHAR rgbIV[] = "abcdefghijklmnop";
static const UCHAR rgbAES128Key[] = "abcdefghijklmnop";

int main()
{
	NTSTATUS status;

	Algorithm alg;
	status = alg.OpenProvider(Algorithm::AES);
	
	DWORD keyLen;
	status = alg.GetProperty(BCRYPT_OBJECT_LENGTH, keyLen);
	Buffer keyObject;
	keyObject.resize(keyLen);
	
	DWORD blockLen;
	status = alg.GetProperty(BCRYPT_BLOCK_LENGTH, blockLen);
	Buffer blockObject;
	blockObject.resize(blockLen);

	Buffer chainMode(BCRYPT_CHAIN_MODE_CBC);
	status = alg.SetProperty(BCRYPT_CHAINING_MODE, chainMode);
	
	Key key(alg);
	Buffer AESKey(rgbAES128Key, rgbAES128Key + sizeof(rgbAES128Key));
	status = key.GenerateSymmetric(keyObject, AESKey);

	Buffer plainText(rgbPlaintext, rgbPlaintext + sizeof(rgbPlaintext));
	Buffer result = key.Encrypt(plainText, (PUCHAR)rgbIV);

	return 0;
}