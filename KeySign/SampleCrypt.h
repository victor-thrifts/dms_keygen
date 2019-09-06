#pragma once
class SampleCrypt
{
private:
	WORD m_Key{ 0 };
public:
	SampleCrypt();
	virtual ~SampleCrypt();
	inline void SetKey(WORD Key){	m_Key = Key;}
	vector<string> getRSAKey();
	string rsa_pub_split128_decrypt(const std::string &encText, std::string &sKey);
	string rsa_pri_split117_encrypt(const std::string &clearText, std::string &sKey);
	int verify(const unsigned char* msg, size_t mlen, const unsigned char* sig, size_t slen, unsigned char* pkey);
	int sign(const unsigned char* msg, size_t mlen, unsigned char** sig, size_t* slen, unsigned char* pkey);
	CString SampleCrypt::Encrypt(CString S); // 加密函数
	CString SampleCrypt::Decrypt(CString S); // 解密函数
};

