//2222119 曹凯伦 信息安全2201班 2024.11.24
#include "MD5.h"
#include "SHA-1.h"
#include "SHA-256.h"
#include "SHA-512.h"
#include "File_hash_LibTomCrypt.h"
#include "File_hash_self.h"

#include <iomanip>
#include <iostream>
#include <string>


using namespace std;


int main()
{   
    //测试自己写的对一般字符串的hash摘要：MD5、SHA-1、SHA-256、SHA-512
    string input = "2221119 CaoKailun Cyberspace Academy";
    cout<<"\n\n\nThe string: "<<input<<"\n\n";

    string hashMD5 = md5_hash(input);
    cout << left << setw(15) << "MD5 hash: " << hashMD5 << std::endl;

    string hash1 = sha1(input);
    cout << left << setw(15) << "SHA-1 hash: " << hash1 << std::endl;

    string hash256 = sha256(input);
    cout << left << setw(15) << "SHA-256 hash: " << hash256 << std::endl;

    string hash512 = sha512(input);
    cout << left << setw(15) << "SHA-512 hash: " << hash512 << std::endl;

    
    //测试两个相似的字符串的md5 hash摘要
    cout<<"\n\n\ntest the difference between two extremely similar strings:\n";
    string a = "22221119 CaoKailun Cyber Safety";
    string b = "22221119 CaoKailun Cyber Safetx";
    cout<< left << setw(20) <<"The first string: "<<a<<endl;
    cout<< left << setw(20) <<"The Second string: "<<b<<endl;
    
    string hashMD5_a = md5_hash(a);
    string hashMD5_b = md5_hash(b);
    cout << left << setw(30) << "The first string's MD5 hash: " << hashMD5_a << std::endl;
    cout << left << setw(30) << "The Second string's MD5 hash: " << hashMD5_b << std::endl;


    //王小云院士 md5碰撞测试
    cout<<"\n\n\nWang Xiaoyun MD5-Collision example:\n";
    string str1 = "TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak";
    string str2 = "TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak";    
    //string str1 = "d131dd02c5e6eec4693d9a0698aff95c2fcab58 712467eab4004583eb8fb7f89 55ad340609f4b30283e48883257 1415a085125e8f7cdc99fd91dbdf 280373c5b d8823e3156348f5bae6dacd436c919c6dd53e2b 487da03fd02396306d248cda0 e99f33420f577ee8ce54b67080a 80d1ec69821bcb6a8839396f9652 b6ff72a70";
    //string str2 = "d131dd02c5e6eec4693d9a0698aff95c2fcab50 712467eab4004583eb8fb7f89 55ad340609f4b30283e4888325f 1415a085125e8f7cdc99fd91dbd7 280373c5b d8823e3156348f5bae6dacd436c919c6dd53e23 487da03fd02396306d248cda0 e99f33420f577ee8ce54b670802 80d1ec69821bcb6a8839396f965a b6ff72a70";


    string hashMD5_str1 = md5_hash(str1);
    string hashMD5_str2 = md5_hash(str2);

    cout <<  "str1: " << str1 << endl;
    cout <<  "str2: " << str2 << endl;
    cout << left << setw(20) << "string str1 MD5 hash: " << hashMD5_str1 << endl;
    cout << left << setw(20) << "string str2 MD5 hash: " << hashMD5_str2 << endl;



    //LibTomCrypt——文件hash摘要
    cout<<"\n\n\nThe hash digest of the file: (with LibTomCrypt)"<<endl;
    //string filename = "./Hash_test_files/info.txt";
    string filename ="./Hash_test_files/md5_Collision.pdf";
    //string filename  = "./main.exe";
    md5_file(filename);
    sha1_file(filename);
    sha256_file(filename);
    sha512_file(filename);



    //测试自己实现的hash函数，对文件的hash摘要
    cout<<"\n\n\nThe hash digest of the file: (with my sha functions)"<<endl;
    //string filename = "./Hash_test_files/info.txt";
    string self_md5_file_hash = self_md5_file(filename);
    cout << left << setw(30) << setfill(' ') << "My own MD5 hash for file: " << self_md5_file_hash << endl;
    
    string self_sha1_file_hash = self_sha1_file(filename);
    cout << left << setw(30) << setfill(' ') << "My own SHA-1 hash for file: " << self_sha1_file_hash << endl;

    string self_sha256_file_hash = self_sha256_file(filename);
    cout << left << setw(30) << setfill(' ') << "My own SHA-256 hash for file: " << self_sha256_file_hash << endl;

    string self_sha512_file_hash = self_sha512_file(filename);
    cout << left << setw(30) << setfill(' ') << "My own SHA-512 hash for file: " << self_sha512_file_hash << endl;

    return 0;

}
