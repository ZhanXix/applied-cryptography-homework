/*
 *		ZhanXix
 *		2019/10/15
 *
 *		SM3长度扩展攻击DEMO
 */

#ifndef _MY_SM3_EXTENSION_ATTACK_H_
#define _MY_SM3_EXTENSION_ATTACK_H_

#include "SM3.h"

//SM3长度扩展攻击
void sm3_extension_attack(unsigned char digest[32], unsigned char* append, int alen, unsigned char output[32]);

//比较两个SM3加密摘要是否一致
int compare_digest(unsigned char digest1[32], unsigned char digest2[32]);

#endif // !_MY_SM3_EXTENSION_ATTACK_H_
