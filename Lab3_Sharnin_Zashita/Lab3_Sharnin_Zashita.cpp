// Lab3_Sharnin_Zashita.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//

#include "pch.h"
#include "framework.h"
#include "Lab3_Sharnin_Zashita.h"
#include <vector>
#ifdef _DEBUG
#define new DEBUG_NEW
#endif
using namespace std;

#pragma comment(lib, "crypt32.lib")
// Единственный объект приложения

CWinApp theApp;

class CryptoAPI
{
	HCRYPTPROV m_hCP = NULL;
	HCRYPTKEY m_hExchangeKey = NULL;
	HCRYPTKEY m_hSessionKey = NULL;
	HCRYPTKEY m_hExportKey = NULL;
public:

	HCRYPTKEY GetExchangeKey()
	{
		return m_hExchangeKey;
	}

	HCRYPTKEY GetSessionKey()
	{
		return m_hSessionKey;
	}

	HCRYPTKEY GetExportKey()
	{
		return m_hExportKey;
	}

	CryptoAPI()
	{
		if (!CryptAcquireContext(&m_hCP, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))	// использование временных ключей, не сохраняющихся в контейнере
			PrintError();
		//		if (!CryptAcquireContext(&m_hCP, "My Container", MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0))
		//		{
		//			if (GetLastError() == NTE_BAD_KEYSET)
		//			{
		//				if (!CryptAcquireContext(&m_hCP, "My Container", MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_NEWKEYSET))
		//					PrintError();
		//			}
		//		}
	}

	~CryptoAPI()
	{
		DestroyKeys();
		if (m_hCP)
		{
			if (!CryptReleaseContext(m_hCP, 0))
				PrintError();
		}
	}

	void GenKeyPair()
	{
		if (!CryptGenKey(m_hCP, CALG_RSA_KEYX, CRYPT_EXPORTABLE, &m_hExchangeKey))
			PrintError();
	}

	void GenSessionKey()
	{
		if (!CryptGenKey(m_hCP, CALG_AES_256, CRYPT_EXPORTABLE, &m_hSessionKey))
			PrintError();
	}

	void GenExportKey(const string& sPassword)
	{
		HCRYPTHASH hHash;
		if (!CryptCreateHash(m_hCP, CALG_SHA_256, NULL, 0, &hHash))
		{
			PrintError();
			return;
		}
		if (!CryptHashData(hHash, (BYTE*)sPassword.c_str(), sPassword.length(), 0))
		{
			PrintError();
			return;
		}

		if (!CryptDeriveKey(m_hCP, CALG_AES_256, hHash, CRYPT_EXPORTABLE, &m_hExportKey))
			PrintError();

		CryptDestroyHash(hHash);
	}

	void DestroyKey(HCRYPTKEY& hKey)
	{
		if (hKey)
		{
			if (!CryptDestroyKey(hKey))
				PrintError();
			hKey = NULL;
		}
	}

	void DestroyKeys()
	{
		DestroyKey(m_hExchangeKey);
		DestroyKey(m_hSessionKey);
		DestroyKey(m_hExportKey);
	}

	void DoExportKey(vector<char>& v, HCRYPTKEY hKey, HCRYPTKEY hExpKey, DWORD dwType)
	{
		DWORD dwLen = 0;
		if (!CryptExportKey(hKey, hExpKey, dwType, 0, NULL, &dwLen))
		{
			PrintError();
			return;
		}
		v.resize(dwLen);
		if (!CryptExportKey(hKey, hExpKey, dwType, 0, (BYTE*)v.data(), &dwLen))
			PrintError();
		v.resize(dwLen);		// поскольку для некоторых ключей реальный размер экспортированных данных 
								// может быть меньше размера, необходимого для экспорта
	}

	void DoImportKey(vector<char>& v, HCRYPTKEY& hKey, HCRYPTKEY hPubKey, DWORD dwType)
	{
		if (!CryptImportKey(m_hCP, (BYTE*)v.data(), v.size(), hPubKey, CRYPT_EXPORTABLE, &hKey))
			PrintError();
	}

	void ExportPublicKey(vector<char>& v)
	{
		DoExportKey(v, m_hExchangeKey, NULL, PUBLICKEYBLOB);
	}

	void ExportPrivateKey(vector<char>& v)
	{
		DoExportKey(v, m_hExchangeKey, m_hExportKey, PRIVATEKEYBLOB);
	}

	void ExportSessionKey(vector<char>& v)
	{
		DoExportKey(v, m_hSessionKey, m_hExchangeKey, SIMPLEBLOB);
	}

	void ImportPublicKey(vector<char>& v)
	{
		DoImportKey(v, m_hExchangeKey, NULL, PUBLICKEYBLOB);
	}

	void ImportPrivateKey(vector<char>& v)
	{
		DoImportKey(v, m_hExchangeKey, m_hExportKey, PRIVATEKEYBLOB);
	}

	void ImportSessionKey(vector<char>& v)
	{
		DoImportKey(v, m_hSessionKey, NULL, SIMPLEBLOB);
	}

	void EncryptData(ifstream& in, ofstream& out, DWORD dwSize, HCRYPTKEY hKey = NULL, bool bRSA = false)
		// CryptGetKeyParam с KP_BLOCKLEN возвращает размер блока в битах, 
		// для большинства алгоритмов можно использовать кратное значение,
		// но RSA требует точного соответствия длине блока в байтах,
		// причем 11 байт нужны для обязательного заполнителя (padding)
	{
		if (!hKey)
			hKey = m_hSessionKey;
		DWORD dwBlockLen = 0;
		DWORD dwDataLen = sizeof(DWORD);
		if (!CryptGetKeyParam(hKey, KP_BLOCKLEN, (BYTE*)&dwBlockLen, &dwDataLen, 0))
			PrintError();
		writeln("Block length: ", dwBlockLen);

		if (bRSA)
		{
			dwBlockLen >>= 3;
			dwBlockLen -= 11;
		}

		DWORD dwDone = 0;
		vector<char> v(dwBlockLen);

		bool bDone = false;
		while (!bDone)
		{
			in.read(v.data(), dwBlockLen);
			DWORD dwRead = (DWORD)in.gcount();
			dwDone += dwRead;
			bDone = (dwDone == dwSize);
			dwDataLen = dwRead;
			if (!CryptEncrypt(hKey, NULL, bDone, 0, NULL, &dwDataLen, 0))
				PrintError();
			if (dwDataLen > v.size())
				v.resize(dwDataLen);
			if (!CryptEncrypt(hKey, NULL, bDone, 0, (BYTE*)v.data(), &dwRead, v.size()))
				PrintError();
			out.write(v.data(), dwRead);
		}
	}

	void DecryptData(ifstream& in, ofstream& out, DWORD dwSize, HCRYPTKEY hKey = NULL, bool bRSA = false)
	{
		if (!hKey)
			hKey = m_hSessionKey;
		DWORD dwBlockLen = 0;
		DWORD dwDataLen = sizeof(DWORD);
		if (!CryptGetKeyParam(hKey, KP_BLOCKLEN, (BYTE*)&dwBlockLen, &dwDataLen, 0))
			PrintError();
		writeln("Block length: ", dwBlockLen);

		if (bRSA)
		{
			dwBlockLen >>= 3;
		}

		DWORD dwDone = 0;
		vector<char> v(dwBlockLen);

		bool bDone = false;
		while (!bDone)
		{
			in.read(v.data(), dwBlockLen);
			DWORD dwRead = (DWORD)in.gcount();
			dwDone += dwRead;
			bDone = (dwDone == dwSize);
			if (!CryptDecrypt(hKey, NULL, bDone, 0, (BYTE*)v.data(), &dwRead))
				PrintError();
			out.write(v.data(), dwRead);
		}
	}

	void EncryptData(vector<char>& vIn, vector<char>& vOut, HCRYPTKEY hKey = NULL, bool bRSA = false)
	{
		if (!hKey)
			hKey = m_hSessionKey;
		DWORD dwBlockLen = 0;
		DWORD dwDataLen = sizeof(DWORD);
		if (!CryptGetKeyParam(hKey, KP_BLOCKLEN, (BYTE*)&dwBlockLen, &dwDataLen, 0))
			PrintError();
		writeln("Block length: ", dwBlockLen);

		if (bRSA)
		{
			dwBlockLen >>= 3;
			dwBlockLen -= 11;
		}

		DWORD dwDone = 0;
		vector<char> v(dwBlockLen);

		bool bDone = false;
		while (!bDone)
		{
			DWORD dwRead = min(dwBlockLen, vIn.size() - dwDone);
			memcpy(v.data(), vIn.data() + dwDone, dwRead);
			dwDone += dwRead;
			bDone = (dwDone == vIn.size());
			dwDataLen = dwRead;
			if (!CryptEncrypt(hKey, NULL, bDone, 0, NULL, &dwDataLen, 0))
				PrintError();
			if (dwDataLen > v.size())
				v.resize(dwDataLen);
			if (!CryptEncrypt(hKey, NULL, bDone, 0, (BYTE*)v.data(), &dwRead, v.size()))
				PrintError();
			vOut.insert(vOut.end(), v.begin(), v.begin() + dwRead);
		}
	}

	void DecryptData(vector<char>& vIn, vector<char>& vOut, HCRYPTKEY hKey = NULL, bool bRSA = false)
	{
		if (!hKey)
			hKey = m_hSessionKey;
		DWORD dwBlockLen = 0;
		DWORD dwDataLen = sizeof(DWORD);
		if (!CryptGetKeyParam(hKey, KP_BLOCKLEN, (BYTE*)&dwBlockLen, &dwDataLen, 0))
			PrintError();
		writeln("Block length: ", dwBlockLen);

		if (bRSA)
		{
			dwBlockLen >>= 3;
		}

		DWORD dwDone = 0;
		vector<char> v(dwBlockLen);

		bool bDone = false;
		while (!bDone)
		{
			DWORD dwRead = min(dwBlockLen, vIn.size() - dwDone);
			memcpy(v.data(), vIn.data() + dwDone, dwRead);
			dwDone += dwRead;
			bDone = (dwDone == vIn.size());
			if (!CryptDecrypt(hKey, NULL, bDone, 0, (BYTE*)v.data(), &dwRead))
				PrintError();
			vOut.insert(vOut.end(), v.begin(), v.begin() + dwRead);
		}
	}
};

void generate_all_keys(CryptoAPI& crypto, string& password) {

	crypto.GenKeyPair();
	crypto.GenExportKey(password);

	{
		vector<char> v;
		crypto.ExportPrivateKey(v);
		ofstream out("private.key", ios::binary);
		out.write(v.data(), v.size());
	}

	{
		vector<char> v;
		crypto.ExportPublicKey(v);
		ofstream out("public.key", ios::binary);
		out.write(v.data(), v.size());
	}

	cout << "Keys were generated and saved" << endl;
}

void encrypt_file(CryptoAPI& crypto, string& filepath) {

	crypto.GenSessionKey();

	vector<char> v1;
	vector<char> v2;

	crypto.ExportSessionKey(v1);
	crypto.EncryptData(v1, v2, crypto.GetExchangeKey(), true);

	ofstream out(filepath + ".enc", ios::binary);
	short int keysize = v2.size();
	out << keysize;
	out << "|";
	out.write(v2.data(), v2.size());

	ifstream in(filepath, ios::binary);

	vector<char> v3;
	vector<char> v4;
	get_vector(v3, in);

	crypto.EncryptData(v3, v4);

	out.write(v4.data(), v4.size());

	crypto.DestroyKeys();
	cout << "File was encrypted" << endl;
}

void decrypt_file(CryptoAPI& crypto, string& filepath) {


	ifstream in(filepath, ios::binary);
	string length;
	vector<char> v1;
	while (true)
	{
		char symb;
		in.get(symb);
		if (symb == '|')
			break;
		length.push_back(symb);
	}
	int int_length = stoi(length);
	for (int i = 0; i < int_length; ++i) {
		char symb;
		in.get(symb);
		v1.push_back(symb);
	}
	vector<char> v2;
	crypto.DecryptData(v1, v2, crypto.GetExchangeKey(), true);
	crypto.ImportSessionKey(v2);

	vector<char> v3;
	vector<char> v4;
	get_vector(v3, in);


	crypto.DecryptData(v3, v4);
	ofstream out(filepath + ".dec", ios::binary);
	out.write(v4.data(), v4.size());

	crypto.DestroyKeys();
	cout << "File was decrypted" << endl;
}

void import_private_key(CryptoAPI& crypto, string& password) {
	crypto.GenExportKey(password);

	{
		ifstream in("private.key", ios::binary);
		vector v(istreambuf_iterator<char>{in}, {});
		crypto.ImportPrivateKey(v);
	}
}
void import_public_key(CryptoAPI& crypto) {
	{
		ifstream in("public.key", ios::binary);
		vector v(istreambuf_iterator<char>{in}, {});
		crypto.ImportPublicKey(v);
	}
}


int main()
{
	int nRetCode = 0;

	HMODULE hModule = ::GetModuleHandle(nullptr);

	if (hModule != nullptr)
	{
		// initialize MFC and print and error on failure
		if (!AfxWinInit(hModule, nullptr, ::GetCommandLine(), 0))
		{
			// TODO: code your application's behavior here.
			wprintf(L"Fatal Error: MFC initialization failed\n");
			nRetCode = 1;
		}
		else
		{
			CryptoAPI crypto;
			while (true)
			{
				cout << "Choose action:" << endl
					<< "0)Exit" << endl
					<< "1)Generate public/private pair" << endl
					<< "2)Encrypt file" << endl
					<< "3)Decrypt file" << endl;
				int selection;
				cin >> selection;
				switch (selection) {

				case 0: {
					return nRetCode;
				}
					  break;
				case 1: {
					string password;
					cout << "Enter password" << endl;
					cin >> password;
					generate_all_keys(crypto, password);
				}
					  break;
				case 2: { ////// Encrypt
					string coding_filepath;
					import_public_key(crypto);
					cout << "Enter file path" << endl;
					cin >> coding_filepath;
					encrypt_file(crypto, coding_filepath);
				}
					  break;
				case 3: { /////// Decrypt
					string decoding_filepath;
					string password;
					cout << "Enter password" << endl;
					cin >> password;
					import_private_key(crypto, password);

					cout << "Enter file path" << endl;
					cin >> decoding_filepath;
					decrypt_file(crypto, decoding_filepath);
				}
					  break;
				default: {
					cout << "Error" << endl;
				}
					   break;
				}
			}
		}
	}
	else
	{
		// TODO: change error code to suit your needs
		wprintf(L"Fatal Error: GetModuleHandle failed\n");
		nRetCode = 1;
	}

	return nRetCode;
}
