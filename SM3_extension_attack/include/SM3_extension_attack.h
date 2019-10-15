/*
 *		ZhanXix
 *		2019/10/15
 *
 *		SM3������չ����DEMO
 */

#ifndef _MY_SM3_EXTENSION_ATTACK_H_
#define _MY_SM3_EXTENSION_ATTACK_H_

#include "SM3.h"

//SM3������չ����
void sm3_extension_attack(unsigned char digest[32], unsigned char* append, int alen, unsigned char output[32]);

//�Ƚ�����SM3����ժҪ�Ƿ�һ��
int compare_digest(unsigned char digest1[32], unsigned char digest2[32]);

#endif // !_MY_SM3_EXTENSION_ATTACK_H_
