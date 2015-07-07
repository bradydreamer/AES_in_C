

#ifndef __CRYPTO_AES_H__
#define __CRYPTO_AES_H__

#ifdef  __cplusplus
   extern "C" {
#endif


/////////////////////////////////////////////////////////////////////////////////////////  AES Block

// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define AES_Nb 4
#define AES_BLOCK_SIZE 16

////////////////////////////////////////// AES Round Key


// bits =             128, 192, 256
// Nk = bits /32 = 4,  6,     8         // The number of 32 bit words in the key. 
// Nr = Nk + 6   =10, 12,   14       //  only for Nb=4
struct aes_key_st {
	unsigned char RoundKey[240];  	// The array that stores the round keys.
	int AES_Nr;                     // The number of rounds in AES Cipher. 
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


#endif // __CRYPTO_AES_H__


