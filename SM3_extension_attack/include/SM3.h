/*
 *		ZhanXix
 *		2019/10/15
 *		�ο���https://github.com/NEWPLAN/SMx
 *
 *		SM3�����㷨
 */

#ifndef _MY_SM3_H_
#define _MY_SM3_H_

typedef struct{
	unsigned long total[2];     //������ֽ���
	unsigned long state[8];     //ժҪ״̬
	unsigned char buffer[64];   //���ڴ�������ݿ�

	unsigned char ipad[64];     //HMAC�ڲ����
	unsigned char opad[64];     //HMAC�ⲿ���
}sm3_context;

//32λ���������꣨��ˣ�
#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
        | ( (unsigned long) (b)[(i) + 1] << 16 )        \
        | ( (unsigned long) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

//sm3�����㷨
void sm3(unsigned char* input, int ilen, unsigned char output[32]);

//*****************************

//��ʼ��SM3_context�ṹ
void sm3_starts(sm3_context* ctx);

//SM3����
//input���������ݵ�buffer��ilen���������ݵĳ���
void sm3_update(sm3_context* ctx, unsigned char* input, int ilen);
void sm3_process(sm3_context* ctx, unsigned char data[64]);

//�ó�����SM3��ϢժҪ
void sm3_finish(sm3_context* ctx, unsigned char output[32]);

#endif // !_MY_SM3_H_
