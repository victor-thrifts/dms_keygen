// openssltest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <openssl/opensslv.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
using namespace std;

#ifdef _DEBUG
#pragma comment(lib, "libcrypto32MTd.lib")
#else
#pragma comment(lib, "libcrypto32MTd.lib")
#endif // DEBUG

#define CipherAlogthm 	  EVP_des_ede3_cbc

// ---- rsa非对称加解密 ---- //   
#define PUB_KEY_FILE "pubkey.pem"    // 公钥路径  
#define PRI_KEY_FILE "prikey.pem"    // 私钥路径  
#define KEY_LENGTH  1024               // 密钥长度
//modulus in format char decimal;
//const char sMODULUS[] = "168471656040682369067024842962822083298669539093986092465366127155720426564118469603013433851342957534348138682751573582625566160744115198034661810651722103097169587486100008061472372333707837160018287515262612680876274406409425481997533147443089198863298280210902750052071080616127252265650629071271842635449";
//const char sPriExponent[] = "150901371025529646290988179678709460820582255579217413062879326125625226668399261526101203807643534082751795733019254351698826384607184496620698500219378204253214947180327085393185504812856350810804446056695865412260029797508072007855612286308169717837624067781580510271891701740762168471560451778085144503393";
//const char sEXPONENT[] = "65537";
const char sMODULUS[] = "115494400298466902885945552139390526520880292706875862994898908709010125650015801180578794092143532867147325627630499286458115490611096410896955708747748653653843323437514358220229483778364630247074884335278011256907371039977009381232358615749264428030722951700128571775730908856995140607781503455169078415733";
const char sPriExponent[] = "102767230013657894651783189236745022720984089433472175268131435088055990925441680971748056479291852223136492271163961821410882476082000811777407756772891061289495611124348649582809948103126997248759918882360665745195401587172936211512567871814103691056860967341917936566979634762403823803089304288708827259233";
const char sEXPONENT[] = "65537";
BIGNUM * modulus = BN_new();
BIGNUM * exponent = BN_new();
BIGNUM * priexpon = BN_new();


// 函数方法生成密钥对   
auto generateRSAKey(std::string strKey[2])->void
{				  
	int ret = -1;
	// 公私密钥对    
	size_t pri_len;
	size_t pub_len;
	char *pri_key = NULL;
	char *pub_key = NULL;

	BN_dec2bn(&modulus, sMODULUS);
	//BN_set_word(exponent, RSA_F4);
	BN_dec2bn(&exponent, sEXPONENT);
	BN_dec2bn(&priexpon, sPriExponent);

	//EVP_PKEY_CTX *evp_ctx = NULL;
	//evp_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	//ret = EVP_PKEY_keygen_init(evp_ctx);
	//EVP_PKEY_CTX_set_rsa_keygen_bits(evp_ctx, KEY_LENGTH);
	//EVP_PKEY_CTX_set_rsa_keygen_pubexp(evp_ctx, exponent);
	//EVP_PKEY_CTX_set_rsa_padding(evp_ctx, RSA_PKCS1_PADDING);
	EVP_PKEY *pkey = EVP_PKEY_new();
	//ret = EVP_PKEY_keygen(evp_ctx, &pkey);

	RSA* rsa = RSA_new_method(NULL);
	//ENGINE_get_default_RSA();		

	// 生成密钥对 
	//ret = RSA_set0_key(rsa, modulus, exponent, priexpon);
	ret = RSA_generate_key_ex(rsa, KEY_LENGTH, exponent, NULL);

	EVP_PKEY_assign_RSA(pkey, rsa);

	const BIGNUM *n, *e, *d;
	RSA_get0_key(rsa, &n, &e, &d);
	cout << "N KEY: " << BN_bn2dec(n) << endl;
	cout << "E KEY: " << BN_bn2hex(e) << endl;
	cout << "D KEY: " << BN_bn2dec(d) << endl;

	BIO *pri = BIO_new(BIO_s_mem());
	BIO *pub = BIO_new(BIO_s_mem());

	//PEM_write_bio_RSAPrivateKey(pri, rsa, NULL, NULL, 0, NULL, NULL);
	PEM_write_bio_PrivateKey(pri, pkey, NULL, NULL, 0, NULL, NULL);
	//PEM_write_bio_RSAPublicKey(pub, rsa);
	PEM_write_bio_PUBKEY(pub, pkey);
	if (ret < 0) {
		ret = ERR_get_error();
		printf("key generation failed\n");
		//printf("%s\n", ERR_error_string(ERR_get_error(), (char *)crip));
	}

	// 获取长度    
	pri_len = BIO_pending(pri);
	pub_len = BIO_pending(pub);

	// 密钥对读取到字符串
	pri_key = (char *)malloc(pri_len + 1);
	pub_key = (char *)malloc(pub_len + 1);

	BIO_read(pri, pri_key, pri_len);
	BIO_read(pub, pub_key, pub_len);

	pri_key[pri_len] = '\0';
	pub_key[pub_len] = '\0';

	// 存储密钥对    
	strKey[0] = pub_key;
	strKey[1] = pri_key;

	// 存储到磁盘（这种方式存储的是begin rsa public key/ begin rsa private key开头的）  
	FILE *pubFile = fopen(PUB_KEY_FILE, "w");
	if (pubFile == NULL)
	{
		assert(false);
		return;
	}
	fputs(pub_key, pubFile);
	fclose(pubFile);

	FILE *priFile = fopen(PRI_KEY_FILE, "w");
	if (priFile == NULL)
	{
		assert(false);
		return;
	}
	fputs(pri_key, priFile);
	fclose(priFile);

	// 内存释放  
	BIO_free_all(pub);
	BIO_free_all(pri);
	free(pri_key);
	free(pub_key);

	//EVP_PKEY_CTX_free(evp_ctx);
	//EVP_PKEY_free(pkey);
	EVP_cleanup();
	//RSA_free(rsa);
}

// 私钥加密
std::string rsa_pri_encrypt(const std::string &clearText, std::string &sKey)
{
	std::string strRet;
	BIO *keybio = BIO_new_mem_buf((unsigned char *)sKey.c_str(), -1);

	EVP_PKEY *evpkey = NULL;
	PEM_read_bio_PrivateKey(keybio, &evpkey, NULL, NULL);
	RSA* rsa = EVP_PKEY_get1_RSA(evpkey);
	//rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	//if (!rsa)
	//{
	//	BIO_free_all(keybio);
	//	return std::string("");
	//}

	int len = RSA_size(rsa);
	char *encryptedText = (char *)malloc(len + 1);
	memset(encryptedText, 0, len + 1);

	// 加密  
	int ret = RSA_private_encrypt(clearText.length(), (const unsigned char*)clearText.c_str(), (unsigned char*)encryptedText, rsa, RSA_PKCS1_PADDING);
	if (ret >= 0)
		strRet = std::string(encryptedText, ret);

	// 释放内存  
	free(encryptedText);
	BIO_free_all(keybio);
	//RSA_free(rsa);
	EVP_cleanup();
	return strRet;
}

// 公钥解密    
std::string rsa_pub_decrypt(const std::string &clearText, std::string &sKey)
{
	std::string strRet;
	BIO *keybio = BIO_new_mem_buf((unsigned char *)sKey.c_str(), -1);

	EVP_PKEY* evpkey = NULL;
	PEM_read_bio_PUBKEY(keybio, &evpkey, NULL, NULL);
	RSA* rsa = EVP_PKEY_get1_RSA(evpkey);
	//rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
	//if (!rsa)
	//{
	//	BIO_free_all(keybio);
	//	return std::string("");
	//}

	int len = RSA_size(rsa);
	//int len = 1028;
	char *encryptedText = (char *)malloc(len + 1);
	memset(encryptedText, 0, len + 1);

	//解密
	int ret = RSA_public_decrypt(clearText.length(), (const unsigned char*)clearText.c_str(), (unsigned char*)encryptedText, rsa, RSA_PKCS1_PADDING);
	if (ret >= 0)
		strRet = std::string(encryptedText, ret);

	// 释放内存  
	free(encryptedText);
	BIO_free_all(keybio);
	//RSA_free(rsa);
	EVP_cleanup();
	return strRet;
}

//私钥加密 + 分片
std::string rsa_pri_split117_encrypt(const std::string &clearText, std::string &sKey)
{
	std::string result;
	std::string input;
	result.clear();
	for (int i = 0; i < clearText.length() / 117; i++)
	{
		input.clear();
		input.assign(clearText.begin() + i * 117, clearText.begin() + i * 117 + 117);
		result = result + rsa_pri_encrypt(input, sKey);
	}
	if (clearText.length() % 117 != 0)
	{
		int tem1 = clearText.length() / 117 * 117;
		int tem2 = clearText.length() - tem1;
		input.clear();
		input.assign(clearText.begin() + tem1, clearText.end());
		result = result + rsa_pri_encrypt(input, sKey);
	}
	return result;
}

//公钥解密 + 分片
std::string rsa_pub_split128_decrypt(const std::string &clearText, std::string &sKey)
{
	//Base64 *base = new Base64();
	std::string result;
	std::string input;
	result.clear();
	for (int i = 0; i< clearText.length() / 128; i++)
	{
		input.clear();
		input.assign(clearText.begin() + i * 128, clearText.begin() + i * 128 + 128);

		result = result + rsa_pub_decrypt(input, sKey);
	}
	if (clearText.length() % 128 != 0)
	{
		int tem1 = clearText.length() / 128 * 128;
		int tem2 = clearText.length() - tem1;
		input.clear();
		input.assign(clearText.begin() + tem1, clearText.end());
		result = result + rsa_pri_encrypt(input, sKey);
	}
	return result;
}

// 公钥加密，这里key必须是公钥
string rsa_pub_encrypt(string& orig_data, string &skey)
{	
	string ret;
	BIO *bp = BIO_new_mem_buf(skey.c_str(), skey.size());
	EVP_PKEY *key = nullptr;
	key = PEM_read_bio_PUBKEY(bp, &key, NULL, NULL);

	EVP_PKEY_CTX *ctx = NULL;	
	ctx = EVP_PKEY_CTX_new(key, NULL);	
	if(NULL == ctx)	{		
		printf("ras_pubkey_encryptfailed to open ctx.\n");		
		EVP_PKEY_free(key);		
		return ret;	
	} 	
	if(EVP_PKEY_encrypt_init(ctx) <= 0)	
	{		
		printf("ras_pubkey_encryptfailed to EVP_PKEY_encrypt_init.\n");		
		EVP_PKEY_free(key);		
		return ret;
	} 	
	unsigned char enc_data[1024];
	size_t enc_data_len;
	if(EVP_PKEY_encrypt(ctx, enc_data, &enc_data_len, (unsigned char*)orig_data.c_str(),  orig_data.size()) <= 0)	{
		printf("ras_pubkey_encryptfailed to EVP_PKEY_encrypt.\n");		
		EVP_PKEY_CTX_free(ctx);		
		EVP_PKEY_free(key); 		
		return ret;
	} 
	ret.assign(string((char*)enc_data, enc_data_len));
	EVP_PKEY_CTX_free(ctx);	
	EVP_PKEY_free(key); 	
	return ret;
}

//密钥解密，这种封装格式只适用公钥加密，私钥解密，这里key必须是私钥
string rsa_pri_decrypt(string &enc_data, string &skey, char *passwd)
{	
	string ret;
	EVP_PKEY *key = NULL;
	BIO* bp = BIO_new_mem_buf(skey.c_str(), skey.size());
	key = PEM_read_bio_PrivateKey(bp, &key, NULL, passwd);
	EVP_PKEY_CTX *ctx = NULL;
	ctx = EVP_PKEY_CTX_new(key, NULL);	
	if(NULL == ctx)	{		
		printf("ras_prikey_decryptfailed to open ctx.\n");		
		EVP_PKEY_free(key);		
		return ret;
	} 	
	if(EVP_PKEY_decrypt_init(ctx) <= 0)	{		
		printf("ras_prikey_decryptfailed to EVP_PKEY_decrypt_init.\n");		
		EVP_PKEY_free(key);		
		return ret;
	} 	
	unsigned char orig_data[1024];
	size_t orig_data_len;
	if (EVP_PKEY_decrypt(ctx, orig_data, &orig_data_len, (unsigned char*)enc_data.c_str(), enc_data.size()) <= 0) { 
		printf("ras_prikey_decryptfailed to EVP_PKEY_decrypt.\n");		
		EVP_PKEY_CTX_free(ctx);		
		EVP_PKEY_free(key); 		
		return ret;
	} 	
	ret = string((char*)orig_data, orig_data_len);
	EVP_PKEY_CTX_free(ctx);	
	EVP_PKEY_free(key);	
	return ret;
}

 //对称加密
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
	int ret, len, ciphertext_len;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	ret = EVP_EncryptInit_ex(ctx, CipherAlogthm(), NULL, key, iv);
	ret = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
	ciphertext_len = len;
	ret = EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
	ciphertext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;
}

//对称解密
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
	int ret, len, plaintext_len;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	ret = EVP_DecryptInit_ex(ctx, CipherAlogthm(), NULL, key, iv);
	ret = EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
	plaintext_len = len;
	ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
	plaintext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return plaintext_len;
}

//performs verification of a string using an HMAC.
int hmac_verify(const unsigned char* msg, size_t mlen, const unsigned char* sig, size_t slen, unsigned char* pkey)
{
	int result = -1;
	if (!msg || !mlen || !sig || !slen || !pkey) return -1;

	EVP_PKEY *evpkey = EVP_PKEY_new();
	BIO *bp = BIO_new(BIO_s_mem());
	BIO_read(bp, (void*)pkey, strlen((const char*)pkey));
	evpkey = PEM_read_bio_PrivateKey(bp, &evpkey, NULL, NULL);

	EVP_MD_CTX* ctx = EVP_MD_CTX_create();
	do
	{
		const EVP_MD* md = EVP_get_digestbyname("SHA1");
		int rc = EVP_DigestInit_ex(ctx, md, NULL);
		rc = EVP_DigestSignInit(ctx, NULL, md, NULL, evpkey);
		rc = EVP_DigestSignUpdate(ctx, msg, mlen);
		unsigned char buff[EVP_MAX_MD_SIZE];
		size_t req = sizeof(buff);
		rc = EVP_DigestSignFinal(ctx, buff, &req);
		const size_t m = (slen < req ? slen : req);
		result = !CRYPTO_memcmp(sig, buff, m);
		OPENSSL_cleanse(buff, sizeof(buff));
	} while (0);
	if (ctx) {
		EVP_MD_CTX_destroy(ctx);
		ctx = NULL;
	}
	return !!result;
}

//Asymmetric Key verify
int verify(const unsigned char* msg, size_t mlen, const unsigned char* sig, size_t slen, unsigned char* pkey)
{
	int result = -1;
	if (!msg || !mlen || !sig || !slen || !pkey) return result;

	EVP_PKEY *evpkey = EVP_PKEY_new();
	BIO *bp = BIO_new(BIO_s_mem());
	BIO_write(bp, pkey, strlen((char*)pkey));
	evpkey = PEM_read_bio_PUBKEY(bp, &evpkey, NULL, NULL);

	EVP_MD_CTX* ctx = EVP_MD_CTX_create();
	do
	{
		const EVP_MD* md = EVP_get_digestbyname("SHA1");
		int rc = EVP_DigestInit_ex(ctx, md, NULL);
		rc = EVP_DigestVerifyInit(ctx, NULL, md, NULL, evpkey);
		rc = EVP_DigestVerifyUpdate(ctx, msg, mlen);
		/* Clear any errors for the call below */
		ERR_clear_error();
		rc = EVP_DigestVerifyFinal(ctx, sig, slen);
		result = 1;
	} while (0);
	if (ctx) {
		EVP_MD_CTX_destroy(ctx);
		ctx = NULL;
	}
	return !!result;
}

//Asymmetric Key sign   OR     hmac  sign;
int sign(const unsigned char* msg, size_t mlen, unsigned char** sig, size_t* slen, unsigned char* pkey)
{
	int result = -1;   *slen = 0;
	if (!msg || !mlen || !sig || !pkey) return result;
	if (*sig) OPENSSL_free(*sig);  *sig = NULL;

	EVP_PKEY *evpkey = EVP_PKEY_new();
	BIO *bp = BIO_new(BIO_s_mem());
	BIO_write(bp, pkey,strlen((char*)pkey));
	//BIO *bp = BIO_new_mem_buf(pkey, -1);

	evpkey = PEM_read_bio_PrivateKey(bp, &evpkey, NULL, NULL);
	char err[128]; printf("%s\n", ERR_error_string(ERR_get_error(), err));

	EVP_MD_CTX* ctx = EVP_MD_CTX_create();
	do
	{
		const EVP_MD* md = EVP_get_digestbyname("SHA1");
		int rc = EVP_DigestInit_ex(ctx, md, NULL);
		rc = EVP_DigestSignInit(ctx, NULL, md, NULL, evpkey);
		rc = EVP_DigestSignUpdate(ctx, msg, mlen);
		size_t req = 0;
		rc = EVP_DigestSignFinal(ctx, NULL, &req);
		*sig = (unsigned char*)OPENSSL_malloc(req);
		*slen = req;
		rc = EVP_DigestSignFinal(ctx, *sig, slen);
		result = 1;
	} while (0);
	if (ctx) {
		EVP_MD_CTX_destroy(ctx);
		ctx = NULL;
	}
	return !!result;
}

int main()
{
	string keypaire[2];
	string plaintext = "AAAAAAAAAAAAAAAAAAA";
	string out;
	generateRSAKey(keypaire);

	out = rsa_pri_split117_encrypt(plaintext, keypaire[1]);
	out = rsa_pub_split128_decrypt(out, keypaire[0]);


	unsigned char *key = (unsigned char *) "key";
	/* A 128 bit IV  Should be hardcoded in both encrypt and decrypt. */
	unsigned char *iv = (unsigned char *)"iv";
	unsigned char ciphertext[128], base64_in[128], base64_out[128];
	/* Buffer for the decrypted text */
	unsigned char decryptedtext[128];
	int decryptedtext_len, ciphertext_len;
	/* Encrypt the plaintext */
	ciphertext_len = encrypt((unsigned char*)plaintext.c_str(), plaintext.size(), key, iv, ciphertext);
	int encode_str_size = EVP_EncodeBlock(base64_out, ciphertext, ciphertext_len);
	/* Decrypt the plaintext */
	memcpy(base64_in, base64_out, 128);
	ciphertext_len = encode_str_size;
	int length = EVP_DecodeBlock(base64_out, base64_in, ciphertext_len);
	while (base64_in[--ciphertext_len] == '=') length--;
	decryptedtext_len = decrypt(base64_out, length, key, iv, decryptedtext);
	decryptedtext[decryptedtext_len] = '\0';

	/* signing and verify */
	unsigned char* sig = NULL; size_t slen = 0;
	sign((unsigned char*)plaintext.c_str(), plaintext.size(), &sig, &slen, (unsigned char*)keypaire[1].c_str());
	verify((unsigned char*)plaintext.c_str(), plaintext.size(), sig, slen, (unsigned char*)keypaire[0].c_str());

	plaintext = rsa_pub_encrypt(plaintext, keypaire[0]);
	plaintext = rsa_pri_decrypt(plaintext, keypaire[1], NULL);
	/* Clean up */
	EVP_cleanup();
	ERR_free_strings();
    return 0;
}

