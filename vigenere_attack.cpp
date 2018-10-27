/*
 * Shahid Beheshti University
 * CS Department
 * Network Security & Cryptography
 * Mr Merdad AhmadZadeh Raji
 *
 * Project: Vigenere Attack
 *
 * team:
 *      Seyyed Rasa Parvini Oskuei
 *      Ali Safari
 *      AmirAbbas Pashayi Hir
 * */

#include <iostream>
using namespace std;

// ------------------------------------------------------------ //
/* FUNCTIONS DECLARTIONS BEGIN */

// below function for cipherText segmentation
string* segmentTheText(const string &, int, string *);

// below function just determine key size
int determineKeySize(const string &cipherText, double treshHold = 0.0085);
// below function know key size and try to determine key values
string determineKeyValue(string* , int, const double *);

// below function compute probability of text validity with real english chars statistics
double validityProbability(string str);
// below function compute probability of text for constant 'char' shift
double computeShiftProbability(string str, int, const double *);

// English standard text probability of chars
double* setFrequency(double *charFrequency);

/* FUNCTIONS DECLARTIONS END */
// ------------------------------------------------------------ //

int main() {

    string cipherText = "ADOIBGQBIAKDTXUGUQTZZGVDCNROHPCYUCBYNSXDBGXNMFLCFNFDUAKAOJFOVYYRLCBGADBCRKCBQNOYLAOVSRAPCRIFWBONKACWSNHBMNYBIFOPODOUIIFBUUQFCEEFZSRIRYLJGCOUMVFZRGXLGTGUGTWNTHNWCRTWYBAQGWGPZZSGADBCJGPSAMVIDTZZTBOSYRYGAUUQKLRSOCFANKVZAYZTUAGYBTZVUGTGUGTWNDVBRYPWSNFFEOHRISGMLVEMRAFJUUQBLCCJZBGUYHMFLCFIUQYLeJZDVBRYPTZRBVFOMNRWNFAFOXYCZVMYQXACTGWBONKACGAQFAMXIPIYDONXDYVTXMPZERUIEKKFNDOMRELZNCQCNYCLNDRZOULDAOTRZMCNHWMFQHOLQIGIIRIKMROXDOQFRYIEQRPEPCNFALOIJMSNCSZVEHEOXROWIDVBRYPTZZPEUQCLADOFKFLUZBSBFFAYHDOMIEGTOECYOJSQEDQMAFYDBYLCLEVWBONKACTZZORZMCNHWMFQFRYQAEZQNECUEEXMPZERUIEKKFNDOOQIFBEVRPYPEFOLRKGIPDKVOQORUJLWIHRPDBUAAOFFFYZGNVWBONKACSCZZJABXQBSWCNSOHCVWMFKBVUGNWYUUQWYRHGYUUMDBCUKZEFFEXGEKJGOMLVYGWNOBFOMPENZBYFRURHWCBQGCYBTZZNRFRIBLSOFEBEVJIKCFQNIEYSANLVMXXQUYBFFFDBYTZZINPLYCNMNJASDBCMWOIBPKMCAJGZNE";
    // if you want to get cipherText from user then uncomment rows: 35 and 36
    string key;
    double* charFrequency = nullptr;

//  set English chars standard probability:
    charFrequency  = setFrequency(charFrequency);

//  get cipherText from user:
//  cout << "Enter cipherText: "
//  cin >> cipherText;

//  determine key size:
    int keySize = determineKeySize(cipherText);
    cout << "keySize: "<< keySize << endl;
    if(keySize == 0){
        cout << "we cant compute key ..." << endl;
        return 0;
    }
    // segments is array with size of keySize
    string *segments = nullptr;
    /*  this means after segmentation all substrings
        will be splited and saved in segments[]  */
    segments = segmentTheText(cipherText, keySize, segments);

    for (int i = 0; i < keySize; i++)
        validityProbability(segments[i]);
    // now, below function determine value of key characters
    key = determineKeyValue(segments, keySize, charFrequency);

    // and show key for decryption!
    cout <<"\nKEY is:  " <<  key << endl;

    // Be Happy!
    return 0;
}


// ------------------------------------------------------------ //
/* FUNCTIONS IMPLEMENTATION BEGIN */

string* segmentTheText(const string &cipherText, int keySize, string *segments){
    /* Arguments description:
     *  cipherText is obvious
     *  keySize was determind with it's function
     *  segments is pointer that saved our segments (keySize numbers)*/
    auto len = static_cast<int>(cipherText.length());
    segments = new string[keySize];
    for(int i=0; i<keySize; i++)
        segments[i] = "";
    for(int i=0; i<keySize; i++){
        int j = i;
        while(j < len){
            segments[i].insert(segments[i].end(), cipherText[j]);
            j += keySize;
        }
    }
    return segments;
}

int determineKeySize(const string &cipherText, double treshHold){
    /* Arguments description:
     *  cipherText is obvious */
    //  we suppose keySize has at most 50 char.
    if (treshHold >=0.03)
        return 0;
    //  below loop, bruthe force to compute best keySize probabilty
    string *segments = nullptr;
    for (int i = 1; i < 50; i++){
        segments = segmentTheText(cipherText, i, segments);
        double ave = 0;
        for (int j = 0; j < i; j++)
            ave += validityProbability(segments[j]);
        ave /= i;
        //  our threshHold is 0.015
        if(abs(ave - 0.065) <= treshHold)
            return i;
    }
    return determineKeySize(cipherText, treshHold  + 0.004);
}

string determineKeyValue(string* segments, int keySize, const double * charFrequency){
    /* Arguments description:
     *  segments is pointer that saved our segments (keySize numbers)
     *  keySize was determined with it's function
     *  charFrequency is English texts char probability */
    // in begin key is empty (we will return key at end)
    string key = "";
    double prob;
    for (int i = 0; i < keySize; i++) {
        //  this loop is determine one char of key at once run...
        double min = 10;
        int index = 0;
        for (int j = 0; j < 26; j++) {
            //  this loop compute shift from A to Z probability and return best of it
            prob = computeShiftProbability(segments[i], j, charFrequency);
            //  in below we save best shift probability and its index
            if (abs(prob - 0.065) < abs(min - 0.065)) {
                min = prob;
                index = j;
            }
        }
        //  at end we insert biggest shift probability in key
        key.insert(key.end(), static_cast<char>(index + 65));
    }
    return key;
}

double validityProbability(string str){
    /* Arguments description:
     *  this function get string str and compute
     *  probability for determined this str is
     *  English normal text or not */

    auto len = static_cast<int>(str.length());
    auto * chars = new int[26];
    for (int j = 0; j < 26; j++)
        chars[j]=0;
    // count str's char frequency
    for (int i = 0; i < len; i++)
        chars[int(str[i]) - 65] ++;
    double fre = 0, tmp = 0;
    // compute probability ...
    for (int i = 0; i < 26; i++) {
        tmp = double(chars[i] * (chars[i] -1));
        fre += tmp;
    }
    fre /= double(len * (len -1));
    return fre;
}
double computeShiftProbability(string str, int index, const double *charFrequency){
    /* Argument description:
     *  string str is text that all computation on this
     *  index is shift index, means this function compute probability based on this
     *  charFrequency is English texts char probability */

    auto len = static_cast<int>(str.length());
    auto * chars = new int[26];
    for (int i = 0; i < 26; i++)
        chars[i] = 0;
    // count str's char frequency
    for (int i = 0; i < len; i++)
        chars[int(str[i]) - 65] ++;

    double  tmp, sum = 0;
    for (int i = 0; i < 26; i++){
        tmp = (charFrequency[i] * 0.01) * (chars[(i + index) % 26] / (double) len);
        sum += tmp;
    }
    // if sum close to 0.065, then this probability is valid and is our answer
    return sum;
}

double* setFrequency(double *charFrequency){
    charFrequency = new double[26];
    charFrequency[0] = 8.167;   // a
    charFrequency[1] = 1.492;   // b
    charFrequency[2] = 2.782;   // c
    charFrequency[3] = 4.253;   // d
    charFrequency[4] = 12.702;  // e
    charFrequency[5] = 2.228;   // f
    charFrequency[6] = 2.015;   // g
    charFrequency[7] = 6.094;   // h
    charFrequency[8] = 6.966;   // i
    charFrequency[9] = 0.153;   // j
    charFrequency[10] = 0.772;  // k
    charFrequency[11] = 4.025;  // l
    charFrequency[12] = 2.406;  // m
    charFrequency[13] = 6.749;  // n
    charFrequency[14] = 7.507;  // o
    charFrequency[15] = 1.929;  // p
    charFrequency[16] = 0.095;  // q
    charFrequency[17] = 5.987;  // r
    charFrequency[18] = 6.327;  // s
    charFrequency[19] = 9.056;  // t
    charFrequency[20] = 2.758;  // u
    charFrequency[21] = 0.978;  // v
    charFrequency[22] = 2.360;  // w
    charFrequency[23] = 0.150;  // x
    charFrequency[24] = 1.974;  // y
    charFrequency[25] = 0.074;  // z
    return charFrequency;
}

/* FUNCTIONS IMPLEMENTATION END */
// ------------------------------------------------------------ //