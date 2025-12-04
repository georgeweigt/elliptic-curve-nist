#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#define INTEGER 2
#define BIT_STRING 3
#define OCTET_STRING 4
#define OID 6
#define UTF8STRING 12
#define PRINTABLE_STRING 19
#define IA5STRING 22
#define UTCTIME 0x17
#define GENERALIZEDTIME 0x18
#define SEQUENCE 0x30
#define SET 0x31

#define RSA_ENCRYPTION 1
#define PRIME256V1 2 // NIST P-256
#define SECP384R1 3 // NIST P-384

// signature algorithms

#define MD5_WITH_RSA_ENCRYPTION 1
#define SHA1_WITH_RSA_ENCRYPTION 2
#define SHA224_WITH_RSA_ENCRYPTION 3
#define SHA256_WITH_RSA_ENCRYPTION 4
#define SHA384_WITH_RSA_ENCRYPTION 5
#define SHA512_WITH_RSA_ENCRYPTION 6

#define ECDSA_WITH_SHA1 7
#define ECDSA_WITH_SHA224 8
#define ECDSA_WITH_SHA256 9
#define ECDSA_WITH_SHA384 10
#define ECDSA_WITH_SHA512 11

struct keyinfo {

	int key_type;

	int line; // debug info

	// rsa

	int modulus_offset;
	int modulus_length;

	int public_exponent_offset;
	int public_exponent_length;

	int private_exponent_offset;
	int private_exponent_length;

	int prime1_offset;
	int prime1_length;

	int prime2_offset;
	int prime2_length;

	int exponent1_offset;
	int exponent1_length;

	int exponent2_offset;
	int exponent2_length;

	int coefficient_offset;
	int coefficient_length;

	// ec

	int ec_oid_offset;
	int ec_oid_length;

	int ec_private_key_offset;
	int ec_private_key_length;

	int ec_public_key_offset;
	int ec_public_key_length;

	// key data

	int key_data_length;
	uint8_t key_data[0];
};

struct certinfo {

	int top_offset;
	int top_length;

	int info_start;
	int info_offset;
	int info_length;

	int serial_number_offset;
	int serial_number_length;

	int algorithm_start;
	int algorithm_offset;
	int algorithm_length;

	int issuer_start;
	int issuer_offset;
	int issuer_length;

	int validity_start;
	int validity_offset;
	int validity_length;

	int subject_start;
	int subject_offset;
	int subject_length;

	int public_key_offset;
	int public_key_length;

	int modulus_offset;
	int modulus_length;

	int exponent_offset;
	int exponent_length;

	int ec_key_offset; // offset of 04 in '04 | X | Y'
	int ec_key_length; // length is 65 for prime256v1, 97 for secp384r1

	int signature_algorithm_offset;
	int signature_algorithm_length;

	int signature_start;
	int signature_offset;
	int signature_length;

	int r_offset; // ecdsa r and s
	int r_length;

	int s_offset;
	int s_length;

	int encryption_algorithm;
					// (type of public key, derived from data at public_key_offset)
					// RSA_ENCRYPTION
					// SECP384R1
					// PRIME256V1

	int signature_algorithm;
					// (derived from data at signature_algorithm_offset)
					// MD5_WITH_RSA_ENCRYPTION
					// SHA1_WITH_RSA_ENCRYPTION
					// SHA224_WITH_RSA_ENCRYPTION
					// SHA256_WITH_RSA_ENCRYPTION
					// SHA384_WITH_RSA_ENCRYPTION
					// SHA512_WITH_RSA_ENCRYPTION
					// ECDSA_WITH_SHA1
					// ECDSA_WITH_SHA224
					// ECDSA_WITH_SHA256
					// ECDSA_WITH_SHA384
					// ECDSA_WITH_SHA512

	time_t not_before;
	time_t not_after;

	int line; // debug info

	int cert_length;
	uint8_t cert_data[0];
};

#define ec_len(p) (p)[-1]
extern int ec_malloc_count;
extern uint32_t *p256, *q256, *gx256, *gy256;
extern uint32_t *p384, *q384, *gx384, *gy384;

struct point {
	uint32_t *x, *y, *z;
};

#define Trace fprintf(stderr, "%s %d\n", __FUNCTION__, __LINE__);

int main(int argc, char *argv[]);
void ec256_encrypt(struct keyinfo *key, uint8_t *hash, int len, uint8_t *sig);
void ec256_encrypt_nib(uint32_t *h, uint32_t *d, uint8_t *sig);
int ec256_verify(struct certinfo *p, struct certinfo *q);
int ec256_verify_nib(uint32_t *h, uint32_t *r, uint32_t *s, uint32_t *x, uint32_t *y);
void ec384_encrypt(struct keyinfo *key, uint8_t *hash, int len, uint8_t *sig);
void ec384_encrypt_nib(uint32_t *h, uint32_t *d, uint8_t *sig);
int ec384_verify(struct certinfo *p, struct certinfo *q);
int ec384_verify_nib(uint32_t *h, uint32_t *r, uint32_t *s, uint32_t *x, uint32_t *y);
uint32_t * ec_modinv(uint32_t *c, uint32_t *p);
void ec_projectify(struct point *S);
int ec_affinify(struct point *S, uint32_t *p);
void ec_double(struct point *R, struct point *S, uint32_t *p);
void ec_add_xyz(struct point *R, struct point *S, struct point *T, uint32_t *p);
void ec_full_add(struct point *R, struct point *S, struct point *T, uint32_t *p);
void ec_full_sub(struct point *R, struct point *S, struct point *T, uint32_t *p);
void ec_mult(struct point *R, uint32_t *d, struct point *S, uint32_t *p);
int ec_get_msbit_index(uint32_t *u);
int ec_get_bit(uint32_t *u, int k);
int ec_F(int t);
void ec_twin_mult(struct point *R, uint32_t *d0, struct point *S, uint32_t *d1, struct point *T, uint32_t *p);
void ec_free_xyz(struct point *u);
uint32_t * ec_add(uint32_t *u, uint32_t *v);
uint32_t * ec_sub(uint32_t *u, uint32_t *v);
uint32_t * ec_mul(uint32_t *u, uint32_t *v);
uint32_t * ec_div(uint32_t *u, uint32_t *v);
void ec_mod(uint32_t *u, uint32_t *v);
uint32_t * ec_pow(uint32_t *u, uint32_t *v);
void ec_shr(uint32_t *u);
int ec_cmp(uint32_t *u, uint32_t *v);
int ec_equal(uint32_t *u, uint32_t v);
uint32_t * ec_int(int k);
uint32_t * ec_new(int n);
void ec_free(uint32_t *p);
uint32_t * ec_dup(uint32_t *u);
void ec_norm(uint32_t *u);
uint32_t * ec_hexstr_to_bignum(char *s);
uint32_t * ec_buf_to_bignum(uint8_t *buf, int len);
void ec_init();
void ec_test();
void ec_test_full_add();
void ec_test_full_sub();
void ec_test_double();
void ec_test_mult();
void ec_test_twin_mult();
void ec_test256();
void ec_test384();
void ecdh_test();
void hmac_sha1(uint8_t *key, int keylen, uint8_t *buf, int len, uint8_t *out);
void sha1(uint8_t *buf, int len, uint8_t *out);
void sha1_with_key(uint8_t *key, uint8_t *buf, int len, uint8_t *out);
void sha1_hash_block(uint8_t *buf, uint32_t *hash);
void hmac_sha224(uint8_t *key, int keylen, uint8_t *buf, int len, uint8_t *out);
void sha224(uint8_t *buf, int len, uint8_t *out);
void sha224_with_key(uint8_t *key, uint8_t *buf, int len, uint8_t *out);
void sha224_hash_block(uint8_t *buf, uint32_t *hash);
void hmac_sha256(uint8_t *key, int keylen, uint8_t *buf, int len, uint8_t *out);
void sha256(uint8_t *buf, int len, uint8_t *out);
void sha256_with_key(uint8_t *key, uint8_t *buf, int len, uint8_t *out);
void sha256_hash_block(uint8_t *buf, uint32_t *hash);
void hmac_sha384(uint8_t *key, int keylen, uint8_t *buf, int len, uint8_t *out);
void sha384(uint8_t *buf, int len, uint8_t *out);
void sha384_with_key(uint8_t *key, uint8_t *buf, int len, uint8_t *out);
void sha384_hash_block(uint8_t *buf, uint64_t *hash);
void hmac_sha512(uint8_t *key, int keylen, uint8_t *buf, int len, uint8_t *out);
void sha512(uint8_t *buf, int len, uint8_t *out);
void sha512_with_key(uint8_t *key, uint8_t *buf, int len, uint8_t *out);
void sha512_hash_block(uint8_t *buf, uint64_t *hash);
