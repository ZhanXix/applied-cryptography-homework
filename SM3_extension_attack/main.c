/*
 *		ZhanXix
 *		2019/10/15
 *
 *		SM3������չ����DEMO
 */

#include "SM3.h"
#include "SM3_extension_attack.h"
#include <stdio.h>

int test_abc()	//������������֤SM3�����㷨�Ƿ���ȷ
{
	unsigned char* input = "abc";
	int ilen = 3;
	unsigned char output[32];
	int i;
	sm3_context ctx;

	printf("Message:\n   %s\n", input);

	sm3(input, ilen, output);
	printf("Encrypted Messeage:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", output[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	putchar('\n');

	/*
	������gmssl�����ϣ�
	$ echo -n "abc" | gmssl sm3
	(stdin)= 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
	*/

	return 0;
}

int main()	//������Ϊ������չ����DEMO
{
	/*
	����Ҫ���͵���Ϣ��"AAAAA"
	�����߸��ӵ���Ϣ��"BBBB"
	���ն�����Ϊ�յ�����Ϣ��"AAAAA"+pad+"BBBB"��
	*/

	unsigned char* message = "AAAAA";
	int ilen = 6;
	unsigned char encrypted_messeage[32];

	int i;

	printf("Message:\n   %s\n", message);
	sm3(message, ilen, encrypted_messeage);

	printf("Encrypted Messeage(True):\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", encrypted_messeage[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	putchar('\n');
	putchar('\n');

	unsigned char* append = "BBBB";
	int append_len = 5;
	unsigned char append_attack_messeage[32];

	sm3_extension_attack(encrypted_messeage, append, append_len, append_attack_messeage);

	printf("Encrypted Messeage(after attack):\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", append_attack_messeage[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	putchar('\n');
	putchar('\n');

	//64 + append_len = 69
	unsigned char fake_message[69] = "AAAAA\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0BBBB";
	int alen = 69;
	fake_message[ilen] = 0x80;
	fake_message[ilen / 64 + 62] = ilen * 8 / 256;
	fake_message[ilen / 64 + 63] = ilen * 8 % 256;

	printf("Fake Message:\n   ");
	for (i = 0; i < alen; i++)
	{
		putchar(fake_message[i]);
	}
	putchar('\n');

	unsigned char fake_encrypted_messeage[32];
	sm3(fake_message, alen, fake_encrypted_messeage);
	
	printf("Fake Encrypted Messeage:\n   ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", fake_encrypted_messeage[i]);
		if (((i + 1) % 4) == 0) printf(" ");
	}
	putchar('\n');
	
	if (compare_digest(append_attack_messeage, fake_encrypted_messeage))
	{	//������ϢժҪ��ͬ
		printf("\nAttack fail!\n");
	}
	else {	//��ϢժҪ��ͬ��������չ�����ɹ�
		printf("\nAttack success!\n");
	}
	return 0;
}
