/*
 * Copyright (C) 2012 Jeremy Kerr <jeremy.kerr@canonical.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the OpenSSL
 * library under certain conditions as described in each individual source file,
 * and distribute linked combinations including the two.
 *
 * You must obey the GNU General Public License in all respects for all
 * of the code used other than OpenSSL. If you modify file(s) with this
 * exception, you may extend this exception to your version of the
 * file(s), but you are not obligated to do so. If you do not wish to do
 * so, delete this exception statement from your version. If you delete
 * this exception statement from all source files in the program, then
 * also delete it here.
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>

#include <getopt.h>

#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>

#include <ccan/talloc/talloc.h>

#include "sha256.h"
#include "idc.h"
#include "image.h"
#include "fileio.h"

/****************************** MACROS ******************************/
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

/**************************** VARIABLES *****************************/
static const WORD k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static const char *toolname = "sbsign";

typedef struct sign_context {
	struct image *image;
	const char *infilename;
	const char *outfilename;
	uint8_t *pcr;
	int verbose;
	int detached;
} sign_context;

static struct option options[] = {
	{ "output", required_argument, NULL, 'o' },
	{ "cert", required_argument, NULL, 'c' },
	{ "key", required_argument, NULL, 'k' },
	{ "golden_pcr", required_argument, NULL, 'g' },
	{ "detached", no_argument, NULL, 'd' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'V' },
	{ NULL, 0, NULL, 0 },
};

static void usage(void)
{
	printf("Usage: %s [options] --key <keyfile> --cert <certfile> "
			"<efi-boot-image>\n"
		"Sign an EFI boot image for use with secure boot.\n\n"
		"Options:\n"
		"\t--key <keyfile>    signing key (PEM-encoded RSA "
						"private key)\n"
		"\t--golden_pcr <golden_pcr_value> signing golden key (direct value)\n"
		"\t--cert <certfile>  certificate (x509 certificate)\n"
		"\t--detached         write a detached signature, instead of\n"
		"\t                    a signed binary\n"
		"\t--output <file>    write signed data to <file>\n"
		"\t                    (default <efi-boot-image>.signed,\n"
		"\t                    or <efi-boot-image>.pk7 for detached\n"
		"\t                    signatures)\n",
		toolname);
}

static void version(void)
{
	printf("%s %s\n", toolname, VERSION);
}

/*********************** SHA FUNCTION DEFINITIONS ***********************/
void sha256_transform(SHA256_CTX_t *ctx, const BYTE data[])
{
	WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for ( ; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

void sha256_init(SHA256_CTX_t *ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX_t *ctx, const BYTE data[], size_t len)
{
	WORD i;

	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			sha256_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

void sha256_final(SHA256_CTX_t *ctx, BYTE hash[])
{
	WORD i;

	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		sha256_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	sha256_transform(ctx, ctx->data);

	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}


/***********************TPM CALCULATION FUNCTION DEFINITIONS ***********************/
void sha256_print(BYTE* in){
	int i = 0;
	char res[65]={0,};
	for(i=0; i<32; i++){
		sprintf(res+(i*2),"%02x",in[i]);
	}
	printf("SHA256:      %s\n",res);
	return ;
}
int sha256_calc(char *line, BYTE* rt_v)
{

	if(!strncmp(line,"GRUB",sizeof(char)*4)){
		printf("this is Grub\n");
		FILE* file = fopen("GRUB.efi","r");
		if(!file){
			printf("fileopen fail\n");
			return -1;
		}
		size_t sizeof_FILE = 614192;
		//fseek(file,0,SEEK_END);
		//size_t sizeof_FILE = ftell(file);
		//fseek(file,0,SEEK_SET);

		void* data =NULL;
		data= malloc(sizeof_FILE);
		if(!data){	
			printf("data malloc fail\n");
			return -1;
		}
		SHA256_CTX_t ctx;
		fread(data,sizeof_FILE,1,file);
		sha256_init(&ctx);
		sha256_update(&ctx, data, sizeof_FILE);
		sha256_final(&ctx, rt_v);
		sha256_print(rt_v);
		free(data);
		return 1;
	}
	else if(!strncmp(line,"KERNEL_1",sizeof(char)*8)){
		printf("this is kernel_2\n");
		FILE* file = fopen("KERNEL.efi","r");
		if(!file){
			printf("fileopen fail\n");
			return -1;
		}
		size_t sizeof_FILE = 7104112;

		void* data =NULL;
		data= malloc(sizeof_FILE);
		if(!data){	
			printf("data malloc fail\n");
			return -1;
		}
		SHA256_CTX_t ctx;
		fread(data,sizeof_FILE,1,file);
		sha256_init(&ctx);
		sha256_update(&ctx, data+0x200,sizeof_FILE-0x200);
		sha256_final(&ctx, rt_v);
		sha256_print(rt_v);
		free(data);
		return 1;
	}
	else if(!strncmp(line,"KERNEL_2",sizeof(char)*8)){
		printf("this is kernel_2\n");
		FILE* file = fopen("KERNEL_2.efi","r");
		if(!file){
			printf("fileopen fail\n");
			return -1;
		}
		size_t sizeof_FILE = 7104528;

		void* data =NULL;
		data= malloc(sizeof_FILE);
		if(!data){	
			printf("data malloc fail\n");
			return -1;
		}
		SHA256_CTX_t ctx;
		fread(data,sizeof_FILE,1,file);
		sha256_init(&ctx);
		sha256_update(&ctx, data+0x200,sizeof_FILE-0x200);
		sha256_final(&ctx, rt_v);
		sha256_print(rt_v);
		free(data);
		return 1;
	}else if(!strncmp(line,"UBUNTU",sizeof(char)*6)){
		printf("this is UBUNTU\n");
		FILE* file = fopen("UBUNTU.txt","r");
		if(!file){
			printf("fileopen fail\n");
			return -1;
		}
		size_t sizeof_FILE =781;

		char* data =NULL;
		data= malloc(sizeof_FILE);
		if(!data){	
			printf("data malloc fail\n");
			return -1;
		}
		SHA256_CTX_t ctx;
		fread(data,sizeof_FILE,1,file);

		size_t len = sizeof_FILE;
		data[len-1]='\0';
		printf("size: %d\n%s\n",len,data);
		sha256_init(&ctx);
		sha256_update(&ctx, (unsigned char*) data, len);
		sha256_final(&ctx, rt_v);
		sha256_print(rt_v);
		free(data);
		return 1;
	}
	else if(!strncmp(line,"MENU",sizeof(char)*4)){
		printf("this is UBUNTU2\n");
		FILE* file = fopen("UBUNTU2.txt","r");
		if(!file){
			printf("fileopen fail\n");
			return -1;
		}
		size_t sizeof_FILE =831;

		char* data =NULL;
		data= malloc(sizeof_FILE);
		if(!data){	
			printf("data malloc fail\n");
			return -1;
		}
		SHA256_CTX_t ctx;
		fread(data,sizeof_FILE,1,file);

		size_t len = strlen(data);
		data[len-1]='\0';
		printf("size: %d\n%s\n",len,data);
		sha256_init(&ctx);
		sha256_update(&ctx, (unsigned char*) data, len);
		sha256_final(&ctx, rt_v);
		sha256_print(rt_v);
		free(data);
		return 1;
	}
	else if(!strncmp(line,"SYSTEM",sizeof(char)*5)){
		printf("this is SYSTEM\n");
		FILE* file = fopen("SYSTEM.txt","r");
		if(!file){
			printf("fileopen fail\n");
			return -1;
		}
		size_t sizeof_FILE =55;
		
		char* data =NULL;
		data= malloc(sizeof_FILE);
		if(!data){	
			printf("data malloc fail\n");
			return -1;
		}
		SHA256_CTX_t ctx;
		fread(data,sizeof_FILE,1,file);

		data[sizeof_FILE-1]='\0';
		printf("size: %d\n%s\n",sizeof_FILE,data);
		sha256_init(&ctx);
		sha256_update(&ctx, (unsigned char*) data, sizeof_FILE);
		sha256_final(&ctx, rt_v);
		sha256_print(rt_v);
		free(data);
		return 1;

	}
	else {
		printf("this is CMD\n");//	size_t sizeof_FILE =615216;
		size_t len = strlen(line);
		len-=1;
		line[len-1]='\0';
		printf("size: %d /// %s\n", len, line);
		SHA256_CTX_t ctx;
		sha256_init(&ctx);
		sha256_update(&ctx, line, len);
		sha256_final(&ctx, rt_v);
		sha256_print(rt_v);
		return 1;
	}
}
void sha256_extend(BYTE* old, BYTE* new)
{
	BYTE cat[64];

	int i =0;
	for(i=0;i<32;i++){
		cat[i]=old[i];
	}
	for(i=0;i<32;i++){
		cat[32+i]=new[i];
	}
	char test[129]={0,};
	for(i=0;i<64;i++){
		sprintf(test+(i*2),"%02x",cat[i]);
	}
	printf("cat: %s\n",test);

	BYTE res[32]={0,};

	SHA256_CTX_t ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, cat, sizeof(cat));
	sha256_final(&ctx, res);	 
	sha256_print(res);

	for(i=0;i<32;i++){
		old[i] = res[i];
	}
	memset(new,0,sizeof(new));
	return ;
}	

void DoTPM_calc(char* version, BYTE* res)
{
	BYTE old[32]={0,};
	BYTE new[32]={0,};

	FILE * file;
	char * line = malloc(sizeof(char)*150);
	size_t len = 150;
	printf("To open: %s\n",version);
	file = fopen(version, "r");
	if(!file){
		printf("ToMeasure open fail\n");
		return 0;
	}

	while(fgets(line, len, file)!= NULL){
		printf( "\nread line :%s", line);
		sha256_calc(line, new);
		sha256_extend(old,new);
		memset(line,0,len);
	}
	free(line);
	memcpy(res, old, sizeof(old));

	return;
}
static void set_default_outfilename(struct sign_context *ctx)
{
	const char *extension;

	extension = ctx->detached ? "pk7" : "signed";

	ctx->outfilename = talloc_asprintf(ctx, "%s.%s",
			ctx->infilename, extension);
}

int DoSBsign(int argc, char **argv)
{
	const char *keyfilename, *certfilename, *golden_pcr_str;
	struct sign_context *ctx;
	uint8_t *buf, *tmp;
	int rc, c, sigsize;

	ctx = talloc_zero(NULL, struct sign_context);

	keyfilename = NULL;
	certfilename = NULL;

	for (;;) {
		int idx;
		c = getopt_long(argc, argv, "o:c:k:g:dvVh", options, &idx);
		if (c == -1)
			break;

		switch (c) {
		case 'o':
			ctx->outfilename = talloc_strdup(ctx, optarg);
			break;
		case 'c':
			certfilename = optarg;
			break;
		case 'k':
			keyfilename = optarg;
			break;
		case 'g':
			{
			unsigned char c[3];
			int i;
			unsigned char *p_tmp;
			//golden_pcr_str = optarg;
			ctx->pcr= malloc(sizeof(BYTE)*32);
			memset(ctx->pcr, 0, sizeof(BYTE)*32);
			DoTPM_calc(optarg, ctx->pcr);
			
			if(!ctx->pcr)
				fprintf(stdout, "Do TPM calc fail\n");
			
			fprintf(stdout, "\n");
			fprintf(stdout, "golden_pcr_value ");
			for (i = 0 ; i < 32 ; i++) {
				fprintf(stdout, "%2X ", ctx->pcr[i]);
			}
			fprintf(stdout, "\n");
			}
			break;
		case 'd':
			ctx->detached = 1;
			break;
		case 'v':
			ctx->verbose = 1;
			break;
		case 'V':
			version();
			return EXIT_SUCCESS;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		}
	}

	if (argc != optind + 1) {
		usage();
		return EXIT_FAILURE;
	}

	ctx->infilename = argv[optind];
	if (!ctx->outfilename)
		set_default_outfilename(ctx);

	if (!certfilename) {
		fprintf(stderr,
			"error: No certificate specified (with --cert)\n");
		usage();
		return EXIT_FAILURE;
	}
	if (!keyfilename) {
		fprintf(stderr,
			"error: No key specified (with --key)\n");
		usage();
		return EXIT_FAILURE;
	}
	if (!ctx->pcr) {
		fprintf(stderr,
			"error: No golden_pcr_value specified (with --golden_pcr)\n");
		usage();
		return EXIT_FAILURE;
	}
			
	ctx->image = image_load(ctx->infilename);
	if (!ctx->image)
		return EXIT_FAILURE;

	talloc_steal(ctx, ctx->image);

	ERR_load_crypto_strings();
	OpenSSL_add_all_digests();
	OpenSSL_add_all_ciphers();

	EVP_PKEY *pkey = fileio_read_pkey(keyfilename);
	if (!pkey)
		return EXIT_FAILURE;

	X509 *cert = fileio_read_cert(certfilename);
	if (!cert)
		return EXIT_FAILURE;

	const EVP_MD *md = EVP_get_digestbyname("SHA256");

	/* set up the PKCS7 object */
	PKCS7 *p7 = PKCS7_new();
	PKCS7_set_type(p7, NID_pkcs7_signed);

	PKCS7_SIGNER_INFO *si = PKCS7_sign_add_signer(p7, cert,
			pkey, md, PKCS7_BINARY);
	if (!si) {
		fprintf(stderr, "error in key/certificate chain\n");
		ERR_print_errors_fp(stderr);
		return EXIT_FAILURE;
	}

	PKCS7_content_new(p7, NID_pkcs7_data);

	rc = IDC_set(p7, si, ctx->image, ctx->pcr);
	if (rc)
		return EXIT_FAILURE;

	sigsize = i2d_PKCS7(p7, NULL);
	tmp = buf = talloc_array(ctx->image, uint8_t, sigsize);
	i2d_PKCS7(p7, &tmp);
	ERR_print_errors_fp(stdout);

	image_add_signature(ctx->image, buf, sigsize);

	if (ctx->detached)
		image_write_detached(ctx->image, ctx->outfilename);
	else
		image_write(ctx->image, ctx->outfilename);

	//TESTING 

	BIO *idcbio;
	idcbio= BIO_new(BIO_s_mem());

	struct idc *checkidc;
	checkidc=IDC_get(p7, idcbio);
	
	if(!checkidc)
		fprintf(stdout, "error getting idc\n");
	
	const unsigned char *idcbuf;
	ASN1_STRING *idcstr;

	idcstr= checkidc->digest->digest;
	idcbuf=ASN1_STRING_data(idcstr);


	fprintf(stdout, "got:       %s\n", idcbuf);
//

	talloc_free(ctx);

	return EXIT_SUCCESS;
}


int main(int argc, char **argv)
{
/*	char* argv_t[10];
	argv_t[0]= "sbsign";
	argv_t[1]= "--key";
	argv_t[2]= "db-custom.key";
	argv_t[3]= "--cert";
	argv_t[4]= "db-custom.crt";
	argv_t[5]= "--golden_pcr";
	argv_t[6]= argv[1];
	argv_t[7]= "--output";
	argv_t[8]= "../grub.tttt.signed.efi";
	argv_t[9]= "../grub.hashextend.efi";
*/

	return	DoSBsign(argc,argv);
}
