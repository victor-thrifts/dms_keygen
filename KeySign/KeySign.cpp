// KeySign.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "KeySign.h"
#include <windows.h>
#include <vector>
#include <time.h>
#include <boost/program_options.hpp>
namespace po = boost::program_options;
using namespace std;

#include "SampleCrypt.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 唯一的应用程序对象

CWinApp theApp;

using namespace std;

CString s_MD5ID("ccccccccccccccccccsssssssssssssssssssssssseeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"@reore90934233;'[[pwerwr!jo3423\gjo4j3tj;ladgj;gamvsaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaeorjwew");

CString GetFileID()
{

	WORD keys[] = { 74042, 75092, 77121, 03030 };

	SampleCrypt crypts[4];

	CString strDecrypt("");
	
	for (int ii = 0; ii < 3; ii++)
	{
		crypts[ii].SetKey(keys[ii]);
		strDecrypt += crypts[ii].Decrypt(s_MD5ID.Mid(ii * 16, 16));
	}
	crypts[3].SetKey(keys[3]);
	strDecrypt += crypts[3].Decrypt(s_MD5ID.Right(s_MD5ID.GetLength() - 48));

	return strDecrypt;
}

int _tmain(int argc, TCHAR* argv[], TCHAR* envp[])
{
	int nRetCode = 0;
	HMODULE hModule = ::GetModuleHandle(NULL);
	if (hModule != NULL)
	{
		// 初始化 MFC 并在失败时显示错误
		if (!AfxWinInit(hModule, NULL, ::GetCommandLine(), 0))
		{
			// TODO:  更改错误代码以符合您的需要
			_tprintf(_T("错误:  MFC 初始化失败\n"));
			nRetCode = 1;
		}
		else
		{
			// TODO:  在此处为应用程序的行为编写代码。
		}
	}
	else
	{
		// TODO:  更改错误代码以符合您的需要
		_tprintf(_T("错误:  GetModuleHandle 失败\n"));
		nRetCode = 1;
	}

	time_t rawtime;
	struct tm * timeinfo;
	char buffer[80];
	time(&rawtime);
	rawtime += 24 * 60 * 60 * 30;
	timeinfo = localtime(&rawtime);
	strftime(buffer, 80, "%Y-%m-%d", timeinfo);

	po::options_description desc("Allowed options");
	desc.add_options()
		("help", "produce help message")
		("id", po::value<int>()->default_value(1), "set production id:\n 1 dms \n  2 das")
		("count", po::value<int>()->default_value(1), "set license permit count.")
		("type", po::value<int>()->default_value(3), "set license type: \n 2  permanent \n 3  perid")
		("date", po::value<string>()->default_value(buffer), "active till the date")
		("company", po::value<string>()->default_value("company"), "company license to")
		("in", po::value<string>(), "the license require file path")
		("out", po::value<string>()->default_value("dms.lic"), "the license file output path")
		;
	po::variables_map vm;
	po::store(po::parse_command_line(argc, argv, desc), vm);
	po::notify(vm);
	if (vm.count("help")) {
		cout << desc << "\n";
		return 0;
	}
	if (vm.count("in")){
		cout << "license request file is " << vm["in"].as<string>() << ".\n";
	}
	else{
		cout << "the license requst file not set.\n";
		return 0;
	}
	cout << "license to company  " << vm["company"].as<string>() << ".\n";
	cout << "license type  was set to " << vm["type"].as<int>() << ".\n";
	if (vm["type"].as<int>() == 3)
		cout << "license to perid days " << vm["date"].as<string>() << ".\n";

	ifstream infile(vm["in"].as<string>(), ios_base::in | ios_base::binary);
	ostringstream sbuf; sbuf << infile.rdbuf();
	sbuf << "LICENSEID=" + to_string(vm["id"].as<int>()) + '\n';
	sbuf << "LICENSETYPE=" + to_string(vm["type"].as<int>()) + '\n';
	sbuf << "PRINTCLIENTCOUNT=" + to_string(vm["count"].as<int>()) + '\n';
	sbuf << "EXPIREDAY=" + vm["date"].as<string>() + '\n';
	sbuf << "LICENSENAME=" + vm["company"].as<string>();
	string plaintext(sbuf.str());


	SampleCrypt ciper;
	vector<string> rr = ciper.getRSAKey();
	unsigned char sig[10240]; size_t sig_len = 0;
	memset(sig, 0, 10240);
	plaintext = ciper.rsa_pri_split117_encrypt(plaintext, rr[1]);
	nRetCode = ciper.sign((unsigned char*)plaintext.c_str(), plaintext.size(), (unsigned char**)&sig, &sig_len, (unsigned char*)rr[1].c_str());
	sbuf.str("");
	string tmpstr((char*)sig, sig_len);
	sbuf << plaintext << "\n\r\n\r" << tmpstr;
	string out = ciper.rsa_pri_split117_encrypt(sbuf.str(), rr[1]);

	ofstream outfile;
	outfile.open(vm["out"].as<string>(), ios_base::ate | ios_base::out | ios_base::binary);
	istringstream sbuf1; sbuf1.str(out);
	sbuf1 >> outfile.rdbuf();
	outfile.close();

	GetFileID();

	return nRetCode;
}
