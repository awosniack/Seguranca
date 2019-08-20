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
	BIGNUM *m1 = BN_new();
	BIGNUM *m2 = BN_new();
	BIGNUM *m1_s = BN_new();
	BIGNUM *m2_s = BN_new();
	BIGNUM *m1_d = BN_new();
	BIGNUM *m2_d = BN_new();
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	BN_dec2bn(&e, "65537");
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	//hexa para assinar - I owe you $2000.
	BN_hex2bn(&m1, "49206f776520796f75202432303030");
	//hexa para assinar - I owe you $3000.
	BN_hex2bn(&m2, "49206f776520796f752024333030302e");

	//assinar com a chave privada
	BN_mod_exp(m1_s, m1, d, n, ctx);
	BN_mod_exp(m2_s, m2, d, n, ctx);
	
	printBN("Assinado - I owe you $2000. = ", m1_s);
	printBN("Assinado - I owe you $3000. = ", m2_s);

	//verificando a assinatura com a chave publica
	BN_mod_exp(m1_d, m1_s, e, n, ctx);
	BN_mod_exp(m2_d, m2_s, e, n, ctx);

	printBN("Verificacao - I owe you $2000. = ", m1_d);
	printBN("Codificacao original           = ", m1);
	printBN("Verificacao - I owe you $3000. = ", m2_d);
	printBN("Codificacao original           = ", m2);
}