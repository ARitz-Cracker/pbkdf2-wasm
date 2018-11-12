#include <stdlib.h>
#include <string.h>

// Based on my PL/SQL implementation (I kid you not)
#define sha512 ((sha512Func*)sha512Ptr)
typedef void sha512Func(unsigned char *out, unsigned char *in, size_t len);

unsigned long sha512Ptr;
void sha512_ptr_set(unsigned long ptr){
    sha512Ptr = ptr;
}

void xorstr(unsigned char *str, size_t len, unsigned char val){
    for (size_t i = 0; i < len; i+=1){
        str[i] ^= val;
    }
}

void xorstrs(unsigned char *str1, unsigned char *str2, size_t len){
    for (size_t i = 0; i < len; i+=1){
        str1[i] ^= str2[i];
    }
}

// note: given result pointer MUST be of length 64
void hmac_sha512(unsigned char *result, unsigned char *salt, size_t saltLen, unsigned char *data, size_t dataLen){
    size_t xorSize = 128;
    if (saltLen > xorSize){
        xorSize = saltLen;
    }

    size_t dataToHashLen = xorSize + dataLen;
    unsigned char *dataToHash;
    dataToHash = (unsigned char*) calloc(dataToHashLen, sizeof(char));
    memcpy(dataToHash, salt, saltLen);
    xorstr(dataToHash, xorSize, 0x36);
    memcpy(dataToHash + xorSize, data, dataLen);

    sha512(result, dataToHash, dataToHashLen);
    free(dataToHash);

    dataToHashLen = xorSize + 64;
    dataToHash = (unsigned char*) calloc(dataToHashLen, sizeof(char));
    memcpy(dataToHash, salt, saltLen);
    xorstr(dataToHash, xorSize, 0x5c);
    memcpy(dataToHash + xorSize, result, 64);

    sha512(result, dataToHash, dataToHashLen);
    free(dataToHash);
}

// note: given result pointer MUST be of length 64 (yes this PBKDF2 implementation is incomplete as I don't allow the key length to be set.)
void pbkdf2_sha512(unsigned char *result, unsigned char *salt, size_t saltLen, unsigned char *data, size_t dataLen, unsigned long iterations){
    unsigned char *prevHash;
    prevHash = (unsigned char*) malloc(64);
    unsigned char *currentHash;
    currentHash = (unsigned char*) malloc(64);

    size_t saltExtraLen = saltLen + 4;
    unsigned char *saltExtra;
    saltExtra = (unsigned char*) malloc(saltExtraLen);
    memcpy(saltExtra, salt, saltLen);

    // This isn't to spec, but I can get away with this since the key length is equal to the hash length.
    saltExtra[saltLen] = 0;
    saltExtra[saltLen + 1] = 0;
    saltExtra[saltLen + 2] = 0;
    saltExtra[saltLen + 3] = 1;

    hmac_sha512(currentHash, data, dataLen, saltExtra, saltExtraLen);
    free(saltExtra);
    memcpy(result, currentHash, 64);
    
    
    for (unsigned long i = 1; i < iterations; i += 1){
        memcpy(prevHash, currentHash, 64);

        hmac_sha512(currentHash, data, dataLen, prevHash, 64);
        xorstrs(result, currentHash, 64);
    }
    free(prevHash);
    free(currentHash);
}
/*
void test_sha512(unsigned char *result, unsigned char *str, size_t len){
    sha512(result, str, len);
}
*/
