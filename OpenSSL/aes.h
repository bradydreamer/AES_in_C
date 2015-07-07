#ifndef __CRYPTO_AES_H__
#define __CRYPTO_AES_H__

#ifdef  __cplusplus
   extern "C" {
#endif


/////////////////////////////////////////////////////////////////////////////////////////  AES Block


/* Because array size can't be a const in C, the following two are macros. Both sizes are in bytes. */
#define AES_Nr_MAX     14
#define AES_BLOCK_SIZE 16

////////////////////////////////////////// AES Round Key


/* This should be a hidden type, but EVP requires that the size be known */
struct aes_key_st {
    unsigned int rd_key[4 *(AES_Nr_MAX + 1)];
    int rounds;
};
typedef struct aes_key_st AES_KEY;


int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);

void Cipher(const unsigned char *in, unsigned char *out, const AES_KEY *key);
void InvCipher(const unsigned char *in, unsigned char *out, const AES_KEY *key);


void AES128_encrypt_block( const unsigned char* inBlock, unsigned char* outBlock, const unsigned char* key128);
void AES128_decrypt_block( const unsigned char* inBlock, unsigned char* outBlock, const unsigned char* key128);



#ifdef  __cplusplus
    }
#endif

#endif /* !__CRYPTO_AES_H__ */
