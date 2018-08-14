/*********************************************************************
* Filename:   sha256.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding SHA1 implementation.
*********************************************************************/

#ifndef SHA256_H
#define SHA256_H

/*************************** HEADER FILES ***************************/
#include <stddef.h>

/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int  WORD;             // 32-bit word, change to "long" for 16-bit machines

typedef struct {
	BYTE data[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[8];
} SHA256_CTX_t;

/*********************** SHA FUNCTION DECLARATIONS **********************/
void sha256_init(SHA256_CTX_t *ctx);
void sha256_update(SHA256_CTX_t *ctx, const BYTE data[], size_t len);
void sha256_final(SHA256_CTX_t *ctx, BYTE hash[]);


/*********************** TPM FUNCTION DECLARATIONS **********************/
void DoTPM_calc(char* version, BYTE* res);
void sha256_extend(BYTE* old, BYTE* new);
int sha256_calc(char *line, BYTE* rt_v);
void sha256_print(BYTE* in);

#endif   // SHA256_H
