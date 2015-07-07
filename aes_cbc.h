#ifndef __CRYPTO_AES_CBC_H__
#define __CRYPTO_AES_CBC_H__

#ifdef  __cplusplus
   extern "C" {
#endif


/////////////////////////////////////////////////////////////////////////////////////////  AES CBC

void memxor(unsigned char* in, unsigned char *out, int n);

unsigned int AES_get_enc_len( unsigned int msgLen );


unsigned int AES_get_dec_len( unsigned char* message,
                               unsigned int  msgLen,
						       unsigned char* key,
                               unsigned char* IV);


unsigned int AES_cbc_encrypt( unsigned char *in, 
							   unsigned char *out, 
							   unsigned int  length, 
							   const AES_KEY *key, 
							   unsigned char *ivec);

unsigned int AES_cbc_decrypt( unsigned char *in, 
							   unsigned char *out, 
							   unsigned int  length, 
							   const AES_KEY *key, 
							   unsigned char *ivec);




/////////////////////////////////////////////////////////////////////////////////////// API wrapper


// note: the order of paramters is different from AES_cbc_encrypt
unsigned int AES128_cbc_encrypt(        const unsigned char* key, 
	                          unsigned char* IV,
 	                          unsigned char* inData, 
                              unsigned int   inLen, 
	                          unsigned char* outData);

unsigned int AES128_cbc_decrypt(        const unsigned char* key, 
	                          unsigned char* IV,
 	                          unsigned char* inData, 
                              unsigned int   inLen, 
	                          unsigned char* outData);


/////////////////////////////////////////////////////////////////////////////////////// 



#ifdef  __cplusplus
    }
#endif

#endif /* !__CRYPTO_AES_CBC_H__ */
