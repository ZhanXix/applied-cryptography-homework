/*
 *		ZhanXix
 *		2019/10/15
 *
 *		SM3长度扩展攻击DEMO
 */

#include "SM3.h"
#include "SM3_extension_attack.h"
#include <stdio.h>

 //SM3长度扩展攻击
unsigned long get_state(unsigned char digest[4])
{
	int i;

	unsigned long result = digest[0] * 16 * 16 * 16 * 16 * 16 * 16 + \
		digest[1] * 16 * 16 * 16 * 16 + digest[2] * 16 * 16 + digest[3];
	return result;
}

void sm3_extension_attack(unsigned char digest[32], unsigned char* append, int alen, unsigned char output[32])
{
	if (alen > 58 || alen < 1)
	{
		printf("ERROR!Append too long!\n");
		return;
	}

	sm3_context ctx;
	sm3_starts(&ctx);

	ctx.state[0] = get_state(&digest[0]);
	ctx.state[1] = get_state(&digest[4]);
	ctx.state[2] = get_state(&digest[8]);
	ctx.state[3] = get_state(&digest[12]);
	ctx.state[4] = get_state(&digest[16]);
	ctx.state[5] = get_state(&digest[20]);
	ctx.state[6] = get_state(&digest[24]);
	ctx.state[7] = get_state(&digest[28]);

	unsigned char input[64] = { 0 };
	int i;

	for (i = 0; i < alen; ++i)
	{
		input[i] = append[i];
	}
	input[alen - 1] = 0x00;
	input[alen] = 0x80;

	int len = 512 + alen * 8;
	input[62] = len / 256;
	input[63] = len % 256;

	
	//直接进行一轮sm3_process
	sm3_process(&ctx, input);

	PUT_ULONG_BE(ctx.state[0], output, 0);
	PUT_ULONG_BE(ctx.state[1], output, 4);
	PUT_ULONG_BE(ctx.state[2], output, 8);
	PUT_ULONG_BE(ctx.state[3], output, 12);
	PUT_ULONG_BE(ctx.state[4], output, 16);
	PUT_ULONG_BE(ctx.state[5], output, 20);
	PUT_ULONG_BE(ctx.state[6], output, 24);
	PUT_ULONG_BE(ctx.state[7], output, 28);
}

//比较两个SM3加密摘要是否一致
int compare_digest(unsigned char digest1[32], unsigned char digest2[32])
{
	int i;
	for (i = 0; i < 32; ++i)
	{
		if (digest1[i] != digest2[i])
		{
			printf("digest1[i] = %x, digest2[i] = %x\n, ERROR!\n", digest1[i], digest2[i]);
			return 1;
		}
	}
	return 0;
}