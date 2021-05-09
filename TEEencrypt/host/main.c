/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt.h>

int main(int argc,char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	int len=64;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;

	printf("========================Encryption========================\n");
	
		printf("arguments : %s \n",argv[1]);
		
		if(strcmp(argv[1],"-e") == 0){
			printf("encoding seq \n");
			//argv[2] = Plaintext.txt
			FILE* fp = fopen(argv[2],"r");
			if(fp == NULL){
				printf("Plaintext.txt does not exist");
				return 0;//if file does not exist, kill process
			}

			char plaintext[64];
			fgets(plaintext,64,fp);	

			printf("plain text is : %s\n",plaintext);
			memcpy(op.params[0].tmpref.buffer, plaintext, len);
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,&err_origin);
			
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",res, err_origin);

			memcpy(ciphertext, op.params[0].tmpref.buffer, len);
			printf("Ciphertext : %s\n", ciphertext);		
			fclose(fp);
			
			//write Ciphertext
			FILE *fc = fopen("/root/Ciphertext.txt","w");
			fprintf(fc,ciphertext);
			fclose(fc);

			//write Ciperkey
			FILE *fk = fopen("/root/Cipherkey.txt","w");
			char cipherkey[64];
			sprintf(cipherkey,"%d",op.params[1].value.a);			
			fprintf(fk,cipherkey);
			fclose(fk);

			printf("enc_key is : %d\n",op.params[1].value.a);
			printf("#######end of encrypt#########\n");
			return 0;
		}
		
		if(strcmp(argv[1],"-d") == 0){
			
			printf("decoding seq \n");
			//argv[2] = "Ciphertext.txt"
			FILE* fc = fopen(argv[2],"r");
			if(fc == NULL){
				printf("Cipertext.txt does not exist");
				return 0;//if file does not exist, kill process
			}
			char ciphertext[64];
			fgets(ciphertext,64,fc);	
			fclose(fc);
			//argv[3] = "Cipherkey.txt"
			FILE* fk = fopen(argv[3],"r");
			char cipherkey[64];
			fgets(cipherkey,64,fk);
			op.params[1].value.a = atoi(cipherkey);
			
			memcpy(op.params[0].tmpref.buffer, ciphertext, len);
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,&err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",res, err_origin);
			memcpy(plaintext, op.params[0].tmpref.buffer, len);
			printf("plain text is : %s\n",plaintext);
			
			//write Plaintext
			FILE *fp = fopen("/root/Plaintext.txt","w");
			fprintf(fp,plaintext);
			fclose(fp);
			printf("########end of decrypt#########\n");
			return 0;

		}
		

	
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
