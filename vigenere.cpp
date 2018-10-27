/*
 * Shahid Beheshti University
 * CS Department
 * Network Security & Cryptography
 * Mr. Mehrdad AhmadZadeh Raji
 *
 * Project: Vigenere Encrypt & Decrypt
 *
 * team:
 *      Seyyed Rasa Parvini Oskuei
 *      Ali Safari
 *      AmirAbbas Pashayi Hir
 * */

#include <iostream>
using namespace std;

int main(){
	
	char table[26][26];
	string plainText;
	string key;
	string cipherText;
	for(int i=0; i<26; i++)
		for(int j=0; j<26; j++)
			table[i][j] = char(((j+i) % 26) + 65);

	cout << "Plaintext: ";
	cin >> plainText;
	cout << "key: ";
	cin >> key;
	cout << "chipherText: ";
	cin >> cipherText;
	
	//Encryption
	for(int i=0; i<plainText.length(); i++)
		cout << table[int(plainText[i])-65][int(key[i%key.length()])-65] << " ";
	cout << endl;
	
	//Decryption
	for(int i=0; i<cipherText.length(); i++)
		cout <<    char((cipherText[i] - key[int(i%key.length())]+26)%26+65)  << " ";
	cout << endl;
	return 0;
}
