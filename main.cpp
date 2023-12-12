#include <iostream>
#include <string>
#include <fstream>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include "cryptopp/cryptlib.h"
#include "cryptopp/pwdbased.h"
#include "cryptopp/sha.h"
#include "cryptopp/hex.h"
#include <cryptopp/aes.h>
#include <cryptopp/files.h>
#include <cryptopp/rijndael.h>
using namespace CryptoPP;
using namespace std;
int main(int argc, char* argv[])
{
    //Пароль, Путь к файлу чтения, Путь к файлу записи, Режим работы
    string pass, input, output, ende;
    cout << "Введите режим en/de:" << endl;
    cin >> ende;
    if(ende == "en") {
        cout << "Создайте пароль:" << endl;
        cin >> pass;
        cout << "Укажите путь к файлу записи:" << endl;
        cin >> input;
        cout << "Укажите путь к файлу чтения:" << endl;
        cin >> output;
        byte bPass[pass.size()];
        StringSource(pass, true, new HexEncoder(new ArraySink(bPass, sizeof(bPass))));
        size_t plen = strlen((const char*)bPass);
        AutoSeededRandomPool GSALT;
        byte SALT[AES::BLOCKSIZE];
        GSALT.GenerateBlock(SALT, sizeof(SALT));
        size_t slen = strlen((const char*)SALT);//
        byte key[SHA256::DIGESTSIZE];
        PKCS12_PBKDF<SHA256> bibl;
        byte purpose = 0;
        bibl.DeriveKey(key, sizeof(key),
                       purpose, bPass,
                       plen, SALT,
                       slen, 1024,
                       0.0f);
        AutoSeededRandomPool GVI;
        byte IV[AES::BLOCKSIZE];
        GVI.GenerateBlock(IV, sizeof(IV));
        ofstream userPass("/home/stud/C++Projects/pr4/cipher/userPass"); //Запись
        StringSource(pass, true, new FileSink(userPass));
        ofstream userKey("/home/stud/C++Projects/pr4/cipher/fileKey");
        ArraySource(key, sizeof(key), true, new FileSink(userKey));
        ofstream userIV("/home/stud/C++Projects/pr4/cipher/fileIV");
        ArraySource(IV, sizeof(IV), true, new FileSink(userIV));
        CBC_Mode<AES>::Encryption ECBC; //ОбЪект дешифратора
        ECBC.SetKeyWithIV(key, sizeof(key), IV);
        ifstream inputf(input);
        ofstream outputf(output);
        FileSource(inputf, true, new StreamTransformationFilter(ECBC, new FileSink(outputf)));
        inputf.close();
        outputf.close();
    } else if(ende == "de") {
        string pass; //Чтение пароля
        cout << "Пароль:" << endl;
        string passNow; //Чтение пароля
        cin >> passNow;
        FileSource("/home/stud/C++Projects/pr4/cipher/userPass",
                   true, new StringSink(pass));

        if (pass != passNow) { //Проверка пароля
            cout << "Неправильный пароль\n";
            return 1;
        }
        cout << "Укажите путь к файлу записи:" << endl;
        cin >> input;
        cout << "Укажите путь к файлу чтения:" << endl;
        cin >> output;
        byte key[SHA256::DIGESTSIZE]; //Чтение ключа
        FileSource("//home/stud/C++Projects/pr4/cipher/fileKey",
                   true, new ArraySink(key, sizeof(key)));

        byte IV[AES::BLOCKSIZE]; //Чтение IV
        FileSource("/home/stud/C++Projects/pr4/cipher/Initial/fileIV",
                   true, new ArraySink(IV, sizeof(IV)));

        CBC_Mode<AES>::Decryption DCBC; //ОбЪект дешифратора
        DCBC.SetKeyWithIV(key, sizeof(key), IV);
        ifstream inputf(input);
        ofstream outputf(output);
        FileSource(inputf, true, new StreamTransformationFilter(DCBC, new FileSink(outputf)));
        inputf.close();
        outputf.close();
    } else {
        cerr << "Ошибка: неправильный режим - " << ende << endl;
        exit(1);
    }
}