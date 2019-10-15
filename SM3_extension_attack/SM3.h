/*
 *		ZhanXix
 *		2019/10/15
 *		参考：https://github.com/NEWPLAN/SMx
 *
 *		SM3加密算法
 */

#ifndef _MY_SM3_H_
#define _MY_SM3_H_

typedef struct{
	unsigned long total[2];     //处理的字节数
	unsigned long state[8];     //摘要状态
	unsigned char buffer[64];   //正在处理的数据块

	unsigned char ipad[64];     //HMAC内部填充
	unsigned char opad[64];     //HMAC外部填充
}sm3_context;

//32位整数操作宏（大端）
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

//sm3加密算法
void sm3(unsigned char* input, int ilen, unsigned char output[32]);

//*****************************

//初始化SM3_context结构
void sm3_starts(sm3_context* ctx);

//SM3更新
//input：保存数据的buffer；ilen：输入数据的长度
void sm3_update(sm3_context* ctx, unsigned char* input, int ilen);
void sm3_process(sm3_context* ctx, unsigned char data[64]);

//得出最终SM3消息摘要
void sm3_finish(sm3_context* ctx, unsigned char output[32]);

#endif // !_MY_SM3_H_
