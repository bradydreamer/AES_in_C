/* created by: nlog2n  on 10 Jan. 2011 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>


#include "STM32/aes.h"
#include "aes_cbc.h"


void memPrint( char* prefix, unsigned char* data, int len );
void strPrint( char* prefix, unsigned char* data, int len );
void dbgPrint( const char *format, ...);


#if (defined(_MSC_VER) && ( defined(_M_IX86) || defined(_M_AMD64) || defined(_M_X64) ) )

     #define CRYPTO_ON_WINDOWS

#else
     //#include "stm32f10x.h"

#endif

				 

void memPrint( char* prefix, unsigned char* data, int len )
{
#ifdef CRYPTO_ON_WINDOWS

	int i;
	printf("%s(%d):     \t", prefix, len);
	for (i=0;i<len;i++){
		if ( i%16 == 0 ) printf("\r\n");
		printf("%02x ", (unsigned char) *(data+i));
	}
	printf("\r\n");

#endif
}


void strPrint( char* prefix, unsigned char* data, int len )
{
#ifdef CRYPTO_ON_WINDOWS

	int i;
	printf("%s(%d) in string:     \t", prefix, len);
	for (i=0;i<len;i++){
		printf("%c", (char) *(data+i));
	}
	printf("\r\n");

#endif
}


// to replace printf()
void dbgPrint( const char *format, ...)
{
#ifdef CRYPTO_ON_WINDOWS
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
#endif
} 




void test_AES_Block()
{
	unsigned char key128[16]     = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char plaintxt[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	unsigned char correctciphertxt[16]= { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
	unsigned char ciphertxt[16] = {0};
	unsigned char decryptedtxt[16] = {0};

	dbgPrint("\r\ntesting AES 128-bit one block...\r\n");
	memPrint("key128 ", key128, 16);
	memPrint("plaintxt", plaintxt, 16);

    AES128_encrypt_block( plaintxt, ciphertxt, key128 );
	memPrint("cipherxt", ciphertxt, 16);

    AES128_decrypt_block( ciphertxt, decryptedtxt, key128 );
	memPrint("decrypted", decryptedtxt, 16);

    if ( !memcmp( ciphertxt, correctciphertxt, 16 ) ) {
	   dbgPrint("cipher successfully.\r\n");
    } else {
	   dbgPrint("<--------------------------------------------------cipher failed!\r\n");
    }

    if ( !memcmp( decryptedtxt, plaintxt, 16 ) ) {
	   dbgPrint("decryption successfully.\r\n");
    } else {
	   dbgPrint("<--------------------------------------------------decryption failed!\r\n");
    }

}


unsigned char KEY1[16]   = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
unsigned char IV1[16] = {0};
unsigned char ZeroIV[16] = {0};

unsigned char plaintxt10[10] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 };
unsigned char plaintxt16[16] =        { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
unsigned char plaintxt17[17] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
                                   ,0x00 };
unsigned char plaintxt32[32] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
                                   ,0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

unsigned char plaintxt33[33] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
                                   ,0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
                                   ,0x00};




unsigned char KEY2[16] = { 0x64, 0x5D, 0xFB, 0x2D, 0x8A, 0xB7, 0x1C, 0x88, 0x4C, 0xEE, 0xF5, 0x59, 0xAF, 0xC8, 0x82, 0x34 };
unsigned char IV2[16] ={ 0x8E, 0x31, 0x8D, 0x69, 0xFA, 0xDA, 0x4A, 0x20, 0xAA, 0xE6, 0x1B, 0xA1, 0xAF, 0xCC, 0x82, 0xFA };

unsigned char plaintxt70[71] = "The sun rose slowly, as if it wasn't sure it was worth all the effort.";
// for reference: the string in bytes
// the number of input bytes, which does not include the last char '\0' of the string.
// if user wants to, can set input length as 71
unsigned char correctciphertxt80[80] =
{ 0x83, 0x33, 0xE4, 0x9F, 0xF2, 0x5C, 0x9D, 0xED, 0x13, 0x34, 0x1A, 0xED, 0x3A, 0x93, 0x2A, 0x08
 ,0x80, 0xFA, 0xF3, 0x74, 0x4E, 0x55, 0x45, 0x10, 0xB4, 0x04, 0xDB, 0xB4, 0xCB, 0x49, 0xA7, 0x22
 ,0x1C, 0xE6, 0x2A, 0x7C, 0x30, 0x06, 0xDE, 0x46, 0xBC, 0x44, 0x51, 0xA6, 0xFA, 0xC6, 0xE2, 0xE9
 ,0xED, 0x64, 0x06, 0x55, 0xAA, 0x1A, 0xC1, 0x28, 0xB2, 0xFE, 0x3F, 0xD2, 0x88, 0x97, 0x29, 0x3D 
 ,0x14, 0xFE, 0x12, 0x8C, 0xB9, 0x7A, 0xA3, 0x6C, 0xFB, 0x04, 0x1B, 0x87, 0xD6, 0xE9, 0x98, 0xA1 };

unsigned char correctdecryptedtxt70[70] = 
{ 0x54, 0x68, 0x65, 0x20, 0x73, 0x75, 0x6E, 0x20, 0x72, 0x6F, 0x73, 0x65, 0x20, 0x73, 0x6C, 0x6F
 ,0x77, 0x6C, 0x79, 0x2C, 0x20, 0x61, 0x73, 0x20, 0x69, 0x66, 0x20, 0x69, 0x74, 0x20, 0x77, 0x61
 ,0x73, 0x6E, 0x27, 0x74, 0x20, 0x73, 0x75, 0x72, 0x65, 0x20, 0x69, 0x74, 0x20, 0x77, 0x61, 0x73
 ,0x20, 0x77, 0x6F, 0x72, 0x74, 0x68, 0x20, 0x61, 0x6C, 0x6C, 0x20, 0x74, 0x68, 0x65, 0x20, 0x65
 ,0x66, 0x66, 0x6F, 0x72, 0x74, 0x2E };






//Mode: AES/CBC/PKCS5Padding
int test_AES_CBC(unsigned char* plaintxt, 
				 unsigned int  len,
				 unsigned char* key128,
				 unsigned char* IV,
				 unsigned char* correctciphertxt,
				 unsigned int  correctcipherlen
				 )
{
   int outLen;
   int succeed = 0;				  

   // The key and plaintext are given in the program itself.
   unsigned char ciphertxt[80] = {0};
   unsigned char decryptedtxt[80] = {0};

   dbgPrint("\r\ntesting AES 128-bit CBC mode...\r\n");
   memPrint("key128  ", key128, 16);
   memPrint("IV  ", IV, 16);
   memPrint("plaintxt", plaintxt, len);
   strPrint("plaintxt", plaintxt, len);

   //
   // encrypt the string, and return the length of ciphered text
   //
   outLen = AES128_cbc_encrypt( key128, IV, plaintxt, len, ciphertxt);

   if ( correctciphertxt ) {
   if ( (outLen == correctcipherlen) && !memcmp( ciphertxt, correctciphertxt, outLen ) ) {
	   dbgPrint("cipher successfully.\r\n");
   } else {
	   dbgPrint("<--------------------------------------------------cipher failed!\r\n");
       memPrint("ciphertxt", ciphertxt, outLen );
	   return 0;
   }
   }

   memPrint("ciphertxt", ciphertxt, outLen );

   //
   // decrypt the ciphered text, and return the length of decrypted data
   //
   outLen = AES128_cbc_decrypt( key128, IV, ciphertxt, outLen, decryptedtxt);


   // check if the decrypted data is the same as the original
   if ( (outLen == len) && !memcmp( decryptedtxt, plaintxt, outLen ) ) {
       succeed = 1; // decryption successfully   	
	   dbgPrint("decryption successfully.\r\n");
   } else {
	   dbgPrint("<--------------------------------------------------decryption failed!\r\n");
       memPrint("decryptedtxt", decryptedtxt, outLen );
	   return 0; // fail
   }

   memPrint("decryptedtxt", decryptedtxt, outLen );
   strPrint("decryptedtxt", decryptedtxt, outLen );
   return succeed;
}










int main(int argc, char* const argv[])
{ 
    int succeed = 1;

	if (1) {
    test_AES_Block();
	}

	if (1) {
    succeed = test_AES_CBC( plaintxt10, 10, KEY1, IV1, 0, 0);
    succeed = test_AES_CBC( plaintxt16, 16, KEY1, IV1, 0, 0);
    succeed = test_AES_CBC( plaintxt17, 17, KEY1, IV1, 0, 0 );
    succeed = test_AES_CBC( plaintxt32, 32, KEY1, IV1, 0, 0 );
    succeed = test_AES_CBC( plaintxt33, 33, KEY1, IV1, 0, 0 );
    succeed = test_AES_CBC( plaintxt70, 70, KEY2, IV2, correctciphertxt80, 80 );
	}

	return succeed;
}


