#include "stdafx.h"
#include <vector>
#include <openssl/opensslv.h>
#include <openssl/rsa.h>
#include <openssl/des.h>
#include <openssl/pem.h>
#include <openssl/err.h>
using namespace std;


#include "SampleCrypt.h"
#ifdef _DEBUG
#pragma comment(lib, "libcrypto.lib")
#else
#pragma comment(lib, "libcrypto.lib")
#endif // DEBUG

// 常量
#define C1 52845
#define C2 22719

// ---- rsa非对称加解密 ---- //   
#define PUB_KEY_FILE "pubkey.pem"    // 公钥路径  
#define PRI_KEY_FILE "prikey.pem"    // 私钥路径  
#define KEY_LENGTH  128               // 密钥长度(字节)

SampleCrypt::SampleCrypt()
{
}


SampleCrypt::~SampleCrypt()
{
}


CString SampleCrypt::Encrypt(CString S) // 加密函数
{
	CString Result, str;
	int i, j;
	WORD Key = m_Key;
	Result = S; // 初始化结果字符串
	for (i = 0; i<S.GetLength(); i++) // 依次对字符串中各字符进行操作
	{
		Result.SetAt(i, S.GetAt(i) ^ (Key >> 8)); // 将密钥移位后与字符异或
		Key = ((BYTE)Result.GetAt(i) + Key)*C1 + C2; // 产生下一个密钥
	}
	S = Result; // 保存结果
	Result.Empty(); // 清除结果
	for (i = 0; i<S.GetLength(); i++) // 对加密结果进行转换
	{
		j = (BYTE)S.GetAt(i); // 提取字符
		// 将字符转换为两个字母保存
		str = "12"; // 设置str长度为2
		str.SetAt(0, 65 + j / 26);
		str.SetAt(1, 65 + j % 26);
		Result += str;
	}
	return Result;
}

CString SampleCrypt::Decrypt(CString S) // 解密函数
{
	CString Result, str;
	int i, j;
	WORD Key = m_Key;
	Result.Empty(); // 清楚结果
	for (i = 0; i < S.GetLength() / 2; i++) // 将字符串两个字母一组进行处理
	{
		j = ((BYTE)S.GetAt(2 * i) - 65) * 26;
		j += (BYTE)S.GetAt(2 * i + 1) - 65;
		str = "1"; // 设置str长度为1
		str.SetAt(0, j);
		Result += str; // 追加字符，还原字符串
	}
	S = Result; // 保存中间结果
	for (i = 0; i<S.GetLength(); i++) // 依次对字符串中各字符进行操作
	{
		Result.SetAt(i, (BYTE)S.GetAt(i) ^ (Key >> 8)); // 将密钥移位后与字符异或
		Key = ((BYTE)S.GetAt(i) + Key)*C1 + C2; // 产生下一个密钥
	}
	return Result;
}

vector<string> SampleCrypt::getRSAKey()
{
	vector<string> ret;
	ifstream infile(PUB_KEY_FILE, ios_base::in | ios_base::binary);
	ostringstream inbuf; inbuf << infile.rdbuf();
	string str(inbuf.str());
	ret.push_back(str);
	infile.close();
	inbuf.str("");

	infile.open(PRI_KEY_FILE, ios_base::in | ios_base::binary);
	inbuf << infile.rdbuf();
	str = inbuf.str();
	ret.push_back(str);
	infile.close();
	return ret;
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

	//RSA* rsa1 = RSA_new_method(NULL);
	////ENGINE_get_default_RSA();	
	//BIGNUM * modulus1 = BN_new();
	//BIGNUM * exponent1 = BN_new();
	//BIGNUM * priexpon1 = BN_new();
	//RSA_get0_key(rsa, (const BIGNUM**)&modulus1, (const BIGNUM**)&exponent1, (const BIGNUM**)&priexpon1);
	//RSA_set0_key(rsa1, modulus1, exponent1, priexpon1);

	int len = RSA_size(rsa);
	char *encryptedText = (char *)malloc(len + 1);
	memset(encryptedText, 0, len + 1);

	// 加密  
	int ret = RSA_private_encrypt(clearText.length(), (const unsigned char*)clearText.c_str(), (unsigned char*)encryptedText, rsa, RSA_PKCS1_PADDING);
	if (ret >= 0){
		strRet = std::string(encryptedText, ret);
	}
	else { char err[128]; printf("%s\n", ERR_error_string(ERR_get_error(), err)); }
	// 释放内存  
	free(encryptedText);
	BIO_free_all(keybio);
	//RSA_free(rsa);
	EVP_cleanup();
	return strRet;
}

// 公钥解密    
std::string rsa_pub_decrypt(const std::string &encText, std::string &sKey)
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

	//RSA* rsa1 = RSA_new_method(NULL);
	////ENGINE_get_default_RSA();	
	//BIGNUM * modulus1 = BN_new();
	//BIGNUM * exponent1 = BN_new();
	//BIGNUM * priexpon1 = BN_new();
	//RSA_get0_key(rsa, (const BIGNUM**)&modulus1, (const BIGNUM**)&exponent1, NULL);
	//BN_set_word(priexpon1, 0);
	//RSA_set0_key(rsa1, modulus1, exponent1, priexpon1);

	int len = RSA_size(rsa);
	char *clearText = (char *)malloc(len + 1);
	memset(clearText, 0, len + 1);

	//解密
	int ret = RSA_public_decrypt(encText.length(), (const unsigned char*)encText.c_str(), (unsigned char*)clearText, rsa, RSA_PKCS1_PADDING);
	if (ret >= 0){ strRet = std::string(clearText, ret); }
	else{ char err[128]; printf("%s\n", ERR_error_string(ERR_get_error(), err)); }


	// 释放内存  
	free(clearText);
	BIO_free_all(keybio);
	//RSA_free(rsa);
	EVP_cleanup();
	return strRet;
}

std::string SampleCrypt::rsa_pri_split117_encrypt(const std::string &clearText, std::string &sKey)
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
std::string SampleCrypt::rsa_pub_split128_decrypt(const std::string &encText, std::string &sKey)
{
	//Base64 *base = new Base64();
	std::string result;
	std::string input;
	result.clear();
	for (int i = 0; i< encText.length() / 128; i++)
	{
		input.clear();
		input.assign(encText.begin() + i * 128, encText.begin() + i * 128 + 128);

		result = result + rsa_pub_decrypt(input, sKey);
	}
	if (encText.length() % 128 != 0)
	{
		int tem1 = encText.length() / 128 * 128;
		int tem2 = encText.length() - tem1;
		input.clear();
		input.assign(encText.begin() + tem1, encText.end());
		result = result + rsa_pub_decrypt(input, sKey);
	}
	return result;
}

//Asymmetric Key verify
int SampleCrypt::verify(const unsigned char* msg, size_t mlen, const unsigned char* sig, size_t slen, unsigned char* pkey)
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
int SampleCrypt::sign(const unsigned char* msg, size_t mlen, unsigned char** sig, size_t* slen, unsigned char* pkey)
{
	int result = -1;   *slen = 0;
	if (!msg || !mlen || !sig || !pkey) return result;
	if (*sig) OPENSSL_free(*sig);  *sig = NULL;

	EVP_PKEY *evpkey = EVP_PKEY_new();
	BIO *bp = BIO_new(BIO_s_mem());
	BIO_write(bp, pkey, strlen((char*)pkey));
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