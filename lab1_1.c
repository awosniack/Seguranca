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
	BIGNUM *n = BN_new();
	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *t = BN_new();
	BIGNUM *q1= BN_new();
	BIGNUM *p1= BN_new();
	BIGNUM *uno=BN_new();
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
	BN_hex2bn(&e, "0D88C3");
	// // n = p*q
	BN_mul(n, p, q, ctx);
	printBN("p * q = ", n);
	//q-1
	BN_dec2bn(&uno, "1");
	BN_sub(q1, q, uno);
	//p-1
	BN_sub(p1, p, uno);
	// t = (p-1)*(q-1)
	BN_mul(t, p1, q1, ctx);
	printBN("p-1 * q-1 = ", t);
	//e*d = 1 mod t -> (e*d) mod t = 1
	BN_mod_inverse(d, e, t, ctx);
	printBN("d = ", d);


}