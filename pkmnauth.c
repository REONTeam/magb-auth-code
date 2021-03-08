/*
DION id: g538175273
pwd: qOl0Q3eK
WWW-Authenticate: GB00 name="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
Authorization: GB00 name="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=KZE9AgyP2V4CFGRiNzvTbi88OnA4PjwyPjr/////////////"
*/

#include <stdio.h>
#include <string.h>

#include "base64.h"
#include "md5.h"

#define BIT(x, n) (((x) >> (n)) & 1)

void weaveBits(char *out, char *in)
{	
	char ch1, ch2;	
	int i;
	
	/* First 18 characters are only the even bits of the string. */
	for (i = 0; i < 18; i++)
	{	
		ch1 = in[i * 2 + 0];
		ch2 = in[i * 2 + 1];
		
		out[i] |= BIT(ch1, 6) << 1 | BIT(ch1, 4) << 2 | BIT(ch1, 2) << 3 | BIT(ch1, 0) << 4;
		out[i] |= BIT(ch2, 6) >> 3 | BIT(ch2, 4) >> 2 | BIT(ch2, 2) >> 1 | BIT(ch2, 0) >> 0;
	}
	
	/* Last 18 characters are only the odd bits of the string. */
	for (; i < 36; i++)
	{
		ch1 = in[i * 2 - 18 + 0];
		ch2 = in[i * 2 - 18 + 1];
		
		out[i] |= BIT(ch1, 7) << 0 | BIT(ch1, 5) << 1 | BIT(ch1, 3) << 2 | BIT(ch1, 1) << 3;
		out[i] |= BIT(ch2, 7) >> 4 | BIT(ch2, 5) >> 3 | BIT(ch2, 3) >> 2 | BIT(ch2, 1) >> 1;
	}
}

void xorAndTradeBits(char *str1, char *str2)
{
	char ch;
	
	/* XOR string 1 with string 2 and trade bit positions 0 -> 3, 3 -> 6, 6 -> 0. */
	for (int i = 0; i < 36; i++)
	{
		ch = str1[i] ^ str2[i];
		str1[i] = (ch & 0b10110110) | BIT(ch, 0) << 3 | BIT(ch, 3) << 6 | BIT(ch, 6) << 0;
	}
}

void md5Calc(const void *data, int len, void *output)
{
	MD5_CTX ctx = {0};
	
	MD5_Init(&ctx);
	MD5_Update(&ctx, data, len);
	MD5_Final(output, &ctx);
}

void genChallengePasswordHash(char *out, char *challenge, char *password)
{
	char stack[100] = {0};
	int sz;
	
	strncpy(stack, challenge, 48);
	sz = strlen(password);
	strncpy(stack + 48, password, sz);
	sz = strlen(stack);
	md5Calc(stack, sz, out);
}

void genChallengeHash(char *challenge, char *userName, char *password, char *out)
{
	char stack[20] = {0};
	int sz;
	
	genChallengePasswordHash(stack, challenge, password);
	strncpy(out, stack, 16);
	sz = strlen(userName);
	strncpy(out + 16, userName, sz);
	sz = strlen(userName);
	memset(out + sz + 16, 0xff, 20 - sz);
}

void scrambleChallenge(int len, char *challenge, char *out)
{
	char stack[80] = {0};
	
	base64_decode(challenge, len, stack);
	weaveBits(stack + 40, stack);
	xorAndTradeBits(out, stack + 40);
}

void genAuthString(char *challenge, char *userName, char *password, char *out)
{
	char stack[200] = {0};
	
	genChallengeHash(challenge, userName, password, stack);
	scrambleChallenge(48, challenge, stack);
	base64_encode(stack, 36, stack + 80);
	base64_decode(challenge, 48, stack + 40);
	base64_encode(stack + 40, 32, stack + 136);
	strcpy(out, stack + 136);
	strcpy(out + 44, stack + 80);
}

int main(int argc, char **argv)
{
	char stack[100] = {0};
	genAuthString(argv[1], argv[2], argv[3], stack);
	printf("Authorization: GB00 name=\"%s\"\n", stack);
	return 0;
}