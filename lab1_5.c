/* bn_sample.c */
#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 128
void printBN(char *msg, BIGNUM * a){
	/* Use BN_bn2hex(a) for hex string
	* Use BN_bn2dec(a) for decimal string */
	char * number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str);
	OPENSSL_free(number_str);
}


int main (){

	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *e = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *n = BN_new();
	BIGNUM *r = BN_new();
	BIGNUM *m = BN_new();
	BIGNUM *m_d = BN_new();
	BIGNUM *m_s = BN_new();
	BIGNUM *s = BN_new();
	BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
	BN_dec2bn(&e, "65537");
	BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
	//Launch a missile. - mensagem codificada em hexa
	BN_hex2bn(&m, "4c61756e63682061206d697373696c652e");

	
	//assinando com a chave S privada
	BN_mod_exp(m_s, s, e, n, ctx);

	//verificando a assinatura com a chave publica
	// BN_mod_exp(m_d, m_s, e, n, ctx);
	printBN("verificacao de assinatura = ", m_s);
}

