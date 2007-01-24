/*
 * HIP userspace crypto functions.
 *
 * HIP userspace crypto functions (for OpenSSL). Code is a combination
 * of original HIPL kernel functions and Boeing HIPD crypto functions.
 *
 * Authors:
 * - Mika Kousa <mkousa@cc.hut.fi>
 * - Miika Komu <miika@iki.fi>
 * - Teemu Koponen <tkoponen@iki.fi>
 * - Abhinav Pathak <abpathak@iitk.ac.in>  
 *
 * Licence: GNU/GPL
 *
 * TODO:
 * - Intergrate ERR_print_errors_fp somehow into HIP_INFO().
 * - No printfs! Daemon has no stderr.
 * - Return values should be from <errno.h>.
 * - Clean up the code!
 * - Use goto err_out, not return 1.
 * - Check that DH key is created exactly as stated in Jokela draft
 *   RFC2412?
 * - Create a function for calculating HIT from DER encoded DSA pubkey
 * - can alloc_and_extract_bin_XX_pubkey() be merged into one function
 * - more consistency in return values: all functions should always return
 *   _negative_, _symbolic_ values (with the exception of zero)
 *
 * BUGS:
 * - "Bad signature r or s size" occurs randomly. This should not happen.
 */

#include "crypto.h"

/*
 * Diffie-Hellman primes
 */

/* 384-bit Group */
unsigned char dhprime_384[] = {
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,
	0x21,0x68,0xC2,0x34,0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,
	0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,0x02,0x0B,0xBE,0xA6,
	0x3B,0x13,0xB2,0x02,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};

/* RFC 2412 Oakley Group 1 768-bit, 96 bytes */
unsigned char dhprime_oakley_1[] = { 
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,
	0x21,0x68,0xC2,0x34,0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,
	0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,0x02,0x0B,0xBE,0xA6,
	0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
	0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,
	0xF2,0x5F,0x14,0x37,0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,
	0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,0xF4,0x4C,0x42,0xE9,
	0xA6,0x3A,0x36,0x20,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};
                                    
/* RFC 3526 MODP 1536-bit = RFC 2412 Oakley Group 5 */
unsigned char dhprime_modp_1536[] = {
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,
	0x21,0x68,0xC2,0x34,0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,
	0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,0x02,0x0B,0xBE,0xA6,
	0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
	0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,
	0xF2,0x5F,0x14,0x37,0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,
	0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,0xF4,0x4C,0x42,0xE9,
	0xA6,0x37,0xED,0x6B,0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
	0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,0xAE,0x9F,0x24,0x11,
	0x7C,0x4B,0x1F,0xE6,0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D,
	0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,0x98,0xDA,0x48,0x36,
	0x1C,0x55,0xD3,0x9A,0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
	0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96,0x1C,0x62,0xF3,0x56,
	0x20,0x85,0x52,0xBB,0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D,
	0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,0xF1,0x74,0x6C,0x08,
	0xCA,0x23,0x73,0x27,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};

/* RFC 3526 MODP 3072-bit, 384 bytes */
unsigned char dhprime_modp_3072[] = {
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,
	0x21,0x68,0xC2,0x34,0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,
	0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,0x02,0x0B,0xBE,0xA6,
	0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
	0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,
	0xF2,0x5F,0x14,0x37,0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,
	0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,0xF4,0x4C,0x42,0xE9,
	0xA6,0x37,0xED,0x6B,0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
	0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,0xAE,0x9F,0x24,0x11,
	0x7C,0x4B,0x1F,0xE6,0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D,
	0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,0x98,0xDA,0x48,0x36,
	0x1C,0x55,0xD3,0x9A,0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
	0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96,0x1C,0x62,0xF3,0x56,
	0x20,0x85,0x52,0xBB,0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D,
	0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,0xF1,0x74,0x6C,0x08,
	0xCA,0x18,0x21,0x7C,0x32,0x90,0x5E,0x46,0x2E,0x36,0xCE,0x3B,
	0xE3,0x9E,0x77,0x2C,0x18,0x0E,0x86,0x03,0x9B,0x27,0x83,0xA2,
	0xEC,0x07,0xA2,0x8F,0xB5,0xC5,0x5D,0xF0,0x6F,0x4C,0x52,0xC9,
	0xDE,0x2B,0xCB,0xF6,0x95,0x58,0x17,0x18,0x39,0x95,0x49,0x7C,
	0xEA,0x95,0x6A,0xE5,0x15,0xD2,0x26,0x18,0x98,0xFA,0x05,0x10,
	0x15,0x72,0x8E,0x5A,0x8A,0xAA,0xC4,0x2D,0xAD,0x33,0x17,0x0D,
	0x04,0x50,0x7A,0x33,0xA8,0x55,0x21,0xAB,0xDF,0x1C,0xBA,0x64,
	0xEC,0xFB,0x85,0x04,0x58,0xDB,0xEF,0x0A,0x8A,0xEA,0x71,0x57,
	0x5D,0x06,0x0C,0x7D,0xB3,0x97,0x0F,0x85,0xA6,0xE1,0xE4,0xC7,
	0xAB,0xF5,0xAE,0x8C,0xDB,0x09,0x33,0xD7,0x1E,0x8C,0x94,0xE0,
	0x4A,0x25,0x61,0x9D,0xCE,0xE3,0xD2,0x26,0x1A,0xD2,0xEE,0x6B,
	0xF1,0x2F,0xFA,0x06,0xD9,0x8A,0x08,0x64,0xD8,0x76,0x02,0x73,
	0x3E,0xC8,0x6A,0x64,0x52,0x1F,0x2B,0x18,0x17,0x7B,0x20,0x0C,
	0xBB,0xE1,0x17,0x57,0x7A,0x61,0x5D,0x6C,0x77,0x09,0x88,0xC0,
	0xBA,0xD9,0x46,0xE2,0x08,0xE2,0x4F,0xA0,0x74,0xE5,0xAB,0x31,
	0x43,0xDB,0x5B,0xFC,0xE0,0xFD,0x10,0x8E,0x4B,0x82,0xD1,0x20,
	0xA9,0x3A,0xD2,0xCA,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};

/* RFC 3526 MODP 6144-bit, 768 bytes */
unsigned char dhprime_modp_6144[] = {
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,
	0x21,0x68,0xC2,0x34,0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,
	0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,0x02,0x0B,0xBE,0xA6,
	0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
	0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,
	0xF2,0x5F,0x14,0x37,0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,
	0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,0xF4,0x4C,0x42,0xE9,
	0xA6,0x37,0xED,0x6B,0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
	0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,0xAE,0x9F,0x24,0x11,
	0x7C,0x4B,0x1F,0xE6,0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D,
	0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,0x98,0xDA,0x48,0x36,
	0x1C,0x55,0xD3,0x9A,0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
	0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96,0x1C,0x62,0xF3,0x56,
	0x20,0x85,0x52,0xBB,0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D,
	0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,0xF1,0x74,0x6C,0x08,
	0xCA,0x18,0x21,0x7C,0x32,0x90,0x5E,0x46,0x2E,0x36,0xCE,0x3B,
	0xE3,0x9E,0x77,0x2C,0x18,0x0E,0x86,0x03,0x9B,0x27,0x83,0xA2,
	0xEC,0x07,0xA2,0x8F,0xB5,0xC5,0x5D,0xF0,0x6F,0x4C,0x52,0xC9,
	0xDE,0x2B,0xCB,0xF6,0x95,0x58,0x17,0x18,0x39,0x95,0x49,0x7C,
	0xEA,0x95,0x6A,0xE5,0x15,0xD2,0x26,0x18,0x98,0xFA,0x05,0x10,
	0x15,0x72,0x8E,0x5A,0x8A,0xAA,0xC4,0x2D,0xAD,0x33,0x17,0x0D,
	0x04,0x50,0x7A,0x33,0xA8,0x55,0x21,0xAB,0xDF,0x1C,0xBA,0x64,
	0xEC,0xFB,0x85,0x04,0x58,0xDB,0xEF,0x0A,0x8A,0xEA,0x71,0x57,
	0x5D,0x06,0x0C,0x7D,0xB3,0x97,0x0F,0x85,0xA6,0xE1,0xE4,0xC7,
	0xAB,0xF5,0xAE,0x8C,0xDB,0x09,0x33,0xD7,0x1E,0x8C,0x94,0xE0,
	0x4A,0x25,0x61,0x9D,0xCE,0xE3,0xD2,0x26,0x1A,0xD2,0xEE,0x6B,
	0xF1,0x2F,0xFA,0x06,0xD9,0x8A,0x08,0x64,0xD8,0x76,0x02,0x73,
	0x3E,0xC8,0x6A,0x64,0x52,0x1F,0x2B,0x18,0x17,0x7B,0x20,0x0C,
	0xBB,0xE1,0x17,0x57,0x7A,0x61,0x5D,0x6C,0x77,0x09,0x88,0xC0,
	0xBA,0xD9,0x46,0xE2,0x08,0xE2,0x4F,0xA0,0x74,0xE5,0xAB,0x31,
	0x43,0xDB,0x5B,0xFC,0xE0,0xFD,0x10,0x8E,0x4B,0x82,0xD1,0x20,
	0xA9,0x21,0x08,0x01,0x1A,0x72,0x3C,0x12,0xA7,0x87,0xE6,0xD7,
	0x88,0x71,0x9A,0x10,0xBD,0xBA,0x5B,0x26,0x99,0xC3,0x27,0x18,
	0x6A,0xF4,0xE2,0x3C,0x1A,0x94,0x68,0x34,0xB6,0x15,0x0B,0xDA,
	0x25,0x83,0xE9,0xCA,0x2A,0xD4,0x4C,0xE8,0xDB,0xBB,0xC2,0xDB,
	0x04,0xDE,0x8E,0xF9,0x2E,0x8E,0xFC,0x14,0x1F,0xBE,0xCA,0xA6,
	0x28,0x7C,0x59,0x47,0x4E,0x6B,0xC0,0x5D,0x99,0xB2,0x96,0x4F,
	0xA0,0x90,0xC3,0xA2,0x23,0x3B,0xA1,0x86,0x51,0x5B,0xE7,0xED,
	0x1F,0x61,0x29,0x70,0xCE,0xE2,0xD7,0xAF,0xB8,0x1B,0xDD,0x76,
	0x21,0x70,0x48,0x1C,0xD0,0x06,0x91,0x27,0xD5,0xB0,0x5A,0xA9,
	0x93,0xB4,0xEA,0x98,0x8D,0x8F,0xDD,0xC1,0x86,0xFF,0xB7,0xDC,
	0x90,0xA6,0xC0,0x8F,0x4D,0xF4,0x35,0xC9,0x34,0x02,0x84,0x92,
	0x36,0xC3,0xFA,0xB4,0xD2,0x7C,0x70,0x26,0xC1,0xD4,0xDC,0xB2,
	0x60,0x26,0x46,0xDE,0xC9,0x75,0x1E,0x76,0x3D,0xBA,0x37,0xBD,
	0xF8,0xFF,0x94,0x06,0xAD,0x9E,0x53,0x0E,0xE5,0xDB,0x38,0x2F,
	0x41,0x30,0x01,0xAE,0xB0,0x6A,0x53,0xED,0x90,0x27,0xD8,0x31,
	0x17,0x97,0x27,0xB0,0x86,0x5A,0x89,0x18,0xDA,0x3E,0xDB,0xEB,
	0xCF,0x9B,0x14,0xED,0x44,0xCE,0x6C,0xBA,0xCE,0xD4,0xBB,0x1B,
	0xDB,0x7F,0x14,0x47,0xE6,0xCC,0x25,0x4B,0x33,0x20,0x51,0x51,
	0x2B,0xD7,0xAF,0x42,0x6F,0xB8,0xF4,0x01,0x37,0x8C,0xD2,0xBF,
	0x59,0x83,0xCA,0x01,0xC6,0x4B,0x92,0xEC,0xF0,0x32,0xEA,0x15,
	0xD1,0x72,0x1D,0x03,0xF4,0x82,0xD7,0xCE,0x6E,0x74,0xFE,0xF6,
	0xD5,0x5E,0x70,0x2F,0x46,0x98,0x0C,0x82,0xB5,0xA8,0x40,0x31,
	0x90,0x0B,0x1C,0x9E,0x59,0xE7,0xC9,0x7F,0xBE,0xC7,0xE8,0xF3,
	0x23,0xA9,0x7A,0x7E,0x36,0xCC,0x88,0xBE,0x0F,0x1D,0x45,0xB7,
	0xFF,0x58,0x5A,0xC5,0x4B,0xD4,0x07,0xB2,0x2B,0x41,0x54,0xAA,
	0xCC,0x8F,0x6D,0x7E,0xBF,0x48,0xE1,0xD8,0x14,0xCC,0x5E,0xD2,
	0x0F,0x80,0x37,0xE0,0xA7,0x97,0x15,0xEE,0xF2,0x9B,0xE3,0x28,
	0x06,0xA1,0xD5,0x8B,0xB7,0xC5,0xDA,0x76,0xF5,0x50,0xAA,0x3D,
	0x8A,0x1F,0xBF,0xF0,0xEB,0x19,0xCC,0xB1,0xA3,0x13,0xD5,0x5C,
	0xDA,0x56,0xC9,0xEC,0x2E,0xF2,0x96,0x32,0x38,0x7F,0xE8,0xD7,
	0x6E,0x3C,0x04,0x68,0x04,0x3E,0x8F,0x66,0x3F,0x48,0x60,0xEE,
	0x12,0xBF,0x2D,0x5B,0x0B,0x74,0x74,0xD6,0xE6,0x94,0xF9,0x1E,
	0x6D,0xCC,0x40,0x24,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};

/* RFC 3526 MODP 8192-bit, 1024 bytes */
unsigned char dhprime_modp_8192[] = {
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,
	0x21,0x68,0xC2,0x34,0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,
	0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,0x02,0x0B,0xBE,0xA6,
	0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
	0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,
	0xF2,0x5F,0x14,0x37,0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,
	0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,0xF4,0x4C,0x42,0xE9,
	0xA6,0x37,0xED,0x6B,0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
	0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,0xAE,0x9F,0x24,0x11,
	0x7C,0x4B,0x1F,0xE6,0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D,
	0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,0x98,0xDA,0x48,0x36,
	0x1C,0x55,0xD3,0x9A,0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
	0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96,0x1C,0x62,0xF3,0x56,
	0x20,0x85,0x52,0xBB,0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D,
	0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,0xF1,0x74,0x6C,0x08,
	0xCA,0x18,0x21,0x7C,0x32,0x90,0x5E,0x46,0x2E,0x36,0xCE,0x3B,
	0xE3,0x9E,0x77,0x2C,0x18,0x0E,0x86,0x03,0x9B,0x27,0x83,0xA2,
	0xEC,0x07,0xA2,0x8F,0xB5,0xC5,0x5D,0xF0,0x6F,0x4C,0x52,0xC9,
	0xDE,0x2B,0xCB,0xF6,0x95,0x58,0x17,0x18,0x39,0x95,0x49,0x7C,
	0xEA,0x95,0x6A,0xE5,0x15,0xD2,0x26,0x18,0x98,0xFA,0x05,0x10,
	0x15,0x72,0x8E,0x5A,0x8A,0xAA,0xC4,0x2D,0xAD,0x33,0x17,0x0D,
	0x04,0x50,0x7A,0x33,0xA8,0x55,0x21,0xAB,0xDF,0x1C,0xBA,0x64,
	0xEC,0xFB,0x85,0x04,0x58,0xDB,0xEF,0x0A,0x8A,0xEA,0x71,0x57,
	0x5D,0x06,0x0C,0x7D,0xB3,0x97,0x0F,0x85,0xA6,0xE1,0xE4,0xC7,
	0xAB,0xF5,0xAE,0x8C,0xDB,0x09,0x33,0xD7,0x1E,0x8C,0x94,0xE0,
	0x4A,0x25,0x61,0x9D,0xCE,0xE3,0xD2,0x26,0x1A,0xD2,0xEE,0x6B,
	0xF1,0x2F,0xFA,0x06,0xD9,0x8A,0x08,0x64,0xD8,0x76,0x02,0x73,
	0x3E,0xC8,0x6A,0x64,0x52,0x1F,0x2B,0x18,0x17,0x7B,0x20,0x0C,
	0xBB,0xE1,0x17,0x57,0x7A,0x61,0x5D,0x6C,0x77,0x09,0x88,0xC0,
	0xBA,0xD9,0x46,0xE2,0x08,0xE2,0x4F,0xA0,0x74,0xE5,0xAB,0x31,
	0x43,0xDB,0x5B,0xFC,0xE0,0xFD,0x10,0x8E,0x4B,0x82,0xD1,0x20,
	0xA9,0x21,0x08,0x01,0x1A,0x72,0x3C,0x12,0xA7,0x87,0xE6,0xD7,
	0x88,0x71,0x9A,0x10,0xBD,0xBA,0x5B,0x26,0x99,0xC3,0x27,0x18,
	0x6A,0xF4,0xE2,0x3C,0x1A,0x94,0x68,0x34,0xB6,0x15,0x0B,0xDA,
	0x25,0x83,0xE9,0xCA,0x2A,0xD4,0x4C,0xE8,0xDB,0xBB,0xC2,0xDB,
	0x04,0xDE,0x8E,0xF9,0x2E,0x8E,0xFC,0x14,0x1F,0xBE,0xCA,0xA6,
	0x28,0x7C,0x59,0x47,0x4E,0x6B,0xC0,0x5D,0x99,0xB2,0x96,0x4F,
	0xA0,0x90,0xC3,0xA2,0x23,0x3B,0xA1,0x86,0x51,0x5B,0xE7,0xED,
	0x1F,0x61,0x29,0x70,0xCE,0xE2,0xD7,0xAF,0xB8,0x1B,0xDD,0x76,
	0x21,0x70,0x48,0x1C,0xD0,0x06,0x91,0x27,0xD5,0xB0,0x5A,0xA9,
	0x93,0xB4,0xEA,0x98,0x8D,0x8F,0xDD,0xC1,0x86,0xFF,0xB7,0xDC,
	0x90,0xA6,0xC0,0x8F,0x4D,0xF4,0x35,0xC9,0x34,0x02,0x84,0x92,
	0x36,0xC3,0xFA,0xB4,0xD2,0x7C,0x70,0x26,0xC1,0xD4,0xDC,0xB2,
	0x60,0x26,0x46,0xDE,0xC9,0x75,0x1E,0x76,0x3D,0xBA,0x37,0xBD,
	0xF8,0xFF,0x94,0x06,0xAD,0x9E,0x53,0x0E,0xE5,0xDB,0x38,0x2F,
	0x41,0x30,0x01,0xAE,0xB0,0x6A,0x53,0xED,0x90,0x27,0xD8,0x31,
	0x17,0x97,0x27,0xB0,0x86,0x5A,0x89,0x18,0xDA,0x3E,0xDB,0xEB,
	0xCF,0x9B,0x14,0xED,0x44,0xCE,0x6C,0xBA,0xCE,0xD4,0xBB,0x1B,
	0xDB,0x7F,0x14,0x47,0xE6,0xCC,0x25,0x4B,0x33,0x20,0x51,0x51,
	0x2B,0xD7,0xAF,0x42,0x6F,0xB8,0xF4,0x01,0x37,0x8C,0xD2,0xBF,
	0x59,0x83,0xCA,0x01,0xC6,0x4B,0x92,0xEC,0xF0,0x32,0xEA,0x15,
	0xD1,0x72,0x1D,0x03,0xF4,0x82,0xD7,0xCE,0x6E,0x74,0xFE,0xF6,
	0xD5,0x5E,0x70,0x2F,0x46,0x98,0x0C,0x82,0xB5,0xA8,0x40,0x31,
	0x90,0x0B,0x1C,0x9E,0x59,0xE7,0xC9,0x7F,0xBE,0xC7,0xE8,0xF3,
	0x23,0xA9,0x7A,0x7E,0x36,0xCC,0x88,0xBE,0x0F,0x1D,0x45,0xB7,
	0xFF,0x58,0x5A,0xC5,0x4B,0xD4,0x07,0xB2,0x2B,0x41,0x54,0xAA,
	0xCC,0x8F,0x6D,0x7E,0xBF,0x48,0xE1,0xD8,0x14,0xCC,0x5E,0xD2,
	0x0F,0x80,0x37,0xE0,0xA7,0x97,0x15,0xEE,0xF2,0x9B,0xE3,0x28,
	0x06,0xA1,0xD5,0x8B,0xB7,0xC5,0xDA,0x76,0xF5,0x50,0xAA,0x3D,
	0x8A,0x1F,0xBF,0xF0,0xEB,0x19,0xCC,0xB1,0xA3,0x13,0xD5,0x5C,
	0xDA,0x56,0xC9,0xEC,0x2E,0xF2,0x96,0x32,0x38,0x7F,0xE8,0xD7,
	0x6E,0x3C,0x04,0x68,0x04,0x3E,0x8F,0x66,0x3F,0x48,0x60,0xEE,
	0x12,0xBF,0x2D,0x5B,0x0B,0x74,0x74,0xD6,0xE6,0x94,0xF9,0x1E,
	0x6D,0xBE,0x11,0x59,0x74,0xA3,0x92,0x6F,0x12,0xFE,0xE5,0xE4,
	0x38,0x77,0x7C,0xB6,0xA9,0x32,0xDF,0x8C,0xD8,0xBE,0xC4,0xD0,
	0x73,0xB9,0x31,0xBA,0x3B,0xC8,0x32,0xB6,0x8D,0x9D,0xD3,0x00,
	0x74,0x1F,0xA7,0xBF,0x8A,0xFC,0x47,0xED,0x25,0x76,0xF6,0x93,
	0x6B,0xA4,0x24,0x66,0x3A,0xAB,0x63,0x9C,0x5A,0xE4,0xF5,0x68,
	0x34,0x23,0xB4,0x74,0x2B,0xF1,0xC9,0x78,0x23,0x8F,0x16,0xCB,
	0xE3,0x9D,0x65,0x2D,0xE3,0xFD,0xB8,0xBE,0xFC,0x84,0x8A,0xD9,
	0x22,0x22,0x2E,0x04,0xA4,0x03,0x7C,0x07,0x13,0xEB,0x57,0xA8,
	0x1A,0x23,0xF0,0xC7,0x34,0x73,0xFC,0x64,0x6C,0xEA,0x30,0x6B,
	0x4B,0xCB,0xC8,0x86,0x2F,0x83,0x85,0xDD,0xFA,0x9D,0x4B,0x7F,
	0xA2,0xC0,0x87,0xE8,0x79,0x68,0x33,0x03,0xED,0x5B,0xDD,0x3A,
	0x06,0x2B,0x3C,0xF5,0xB3,0xA2,0x78,0xA6,0x6D,0x2A,0x13,0xF8,
	0x3F,0x44,0xF8,0x2D,0xDF,0x31,0x0E,0xE0,0x74,0xAB,0x6A,0x36,
	0x45,0x97,0xE8,0x99,0xA0,0x25,0x5D,0xC1,0x64,0xF3,0x1C,0xC5,
	0x08,0x46,0x85,0x1D,0xF9,0xAB,0x48,0x19,0x5D,0xED,0x7E,0xA1,
	0xB1,0xD5,0x10,0xBD,0x7E,0xE7,0x4D,0x73,0xFA,0xF3,0x6B,0xC3,
	0x1E,0xCF,0xA2,0x68,0x35,0x90,0x46,0xF4,0xEB,0x87,0x9F,0x92,
	0x40,0x09,0x43,0x8B,0x48,0x1C,0x6C,0xD7,0x88,0x9A,0x00,0x2E,
	0xD5,0xEE,0x38,0x2B,0xC9,0x19,0x0D,0xA6,0xFC,0x02,0x6E,0x47,
	0x95,0x58,0xE4,0x47,0x56,0x77,0xE9,0xAA,0x9E,0x30,0x50,0xE2,
	0x76,0x56,0x94,0xDF,0xC8,0x1F,0x56,0xE8,0x80,0xB9,0x6E,0x71,
	0x60,0xC9,0x80,0xDD,0x98,0xED,0xD3,0xDF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF
};

/* load DH arrays for easy access */
const unsigned char *dhprime[HIP_MAX_DH_GROUP_ID] = {
        0,
        dhprime_384,
        dhprime_oakley_1,
        dhprime_modp_1536,
        dhprime_modp_3072,
        dhprime_modp_6144,
        dhprime_modp_8192,
};

int dhprime_len[HIP_MAX_DH_GROUP_ID] = {
        -1,
        sizeof(dhprime_384),
        sizeof(dhprime_oakley_1),
        sizeof(dhprime_modp_1536),
        sizeof(dhprime_modp_3072),
        sizeof(dhprime_modp_6144),
        sizeof(dhprime_modp_8192),
};

unsigned char dhgen[HIP_MAX_DH_GROUP_ID] = {0,0x02,0x02,0x02,0x02,0x02,0x02};

/**
 * hip_build_digest - calculate a digest over given data
 * @param type the type of digest, e.g. "sha1"
 * @param in the beginning of the data to be digested
 * @param in_len the length of data to be digested in octets
 * @param out the digest
 *
 * @param out should be long enough to hold the digest. This cannot be
 * checked!
 *
 * @return 0 on success, otherwise < 0.
 */
int hip_build_digest(const int type, const void *in, int in_len, void *out) {
	SHA_CTX sha;
	MD5_CTX md5;

	switch(type) {
	case HIP_DIGEST_SHA1:
		SHA1_Init(&sha);
		SHA1_Update(&sha, in, in_len);
		SHA1_Final(out, &sha);
		break;

	case HIP_DIGEST_MD5:
		MD5_Init(&md5);
		MD5_Update(&md5, in, in_len);
		MD5_Final(out, &md5);
		break;

	default:
		HIP_ERROR("Unknown digest: %x\n",type);
		return -EFAULT;
	}

	return 0;
}

/**
 * Calculates a hmac.
 * 
 * @param type   type (digest algorithm) of hmac.
 * @param key    a pointer to the key used for hmac.
 * @param in     a pointer to the input buffer.
 * @param in_len the length of the input buffer @c in.
 * @param out    a pointer to the output buffer. For SHA1-HMAC this is 160bits.
 * @return       1 if ok, zero otherwise.
 * @warning      This function returns 1 for success which is against the policy
 *               defined in @c /doc/HACKING.
 * @todo         Should this function return zero for success?
 */
int hip_write_hmac(int type, void *key, void *in, int in_len, void *out)
{
	HIP_HEXDUMP("Dumping key", key, 20);
	switch(type) {
        case HIP_DIGEST_SHA1_HMAC:
                HMAC(EVP_sha1(), 
                     key,
		     hip_hmac_key_length(HIP_ESP_AES_SHA1),
		     in, in_len,
		     out, NULL);
                break;

        case HIP_DIGEST_MD5_HMAC:
                HMAC(EVP_md5(), 
		     key,
		     hip_hmac_key_length(HIP_ESP_3DES_MD5),
		     in, in_len,
		     out, NULL);
                break;
        default:
                HIP_ERROR("Unknown HMAC type 0x%x\n", type);
                return 0;
        }

	HIP_HEXDUMP("HMAC key", key, hip_hmac_key_length(HIP_ESP_AES_SHA1));
	HIP_HEXDUMP("hmac in", in, in_len);
	HIP_HEXDUMP("hmac out", out, HIP_AH_SHA_LEN);

	return 1;
}

/**
 * hip_crypto_encrypted - encrypt/decrypt data
 * @param data data to be encrypted/decrypted
 * @param iv_orig initialization vector
 * @param alg encryption algorithm to use
 * @param len length of data
 * @param key encryption/decryption key to use
 * @param direction flag for selecting encryption/decryption
 *
 * @param direction is HIP_DIRECTION_ENCRYPT if data is to be encrypted
 * or HIP_DIRECTION_DECRYPT if data is to be decrypted.
 *
 * The result of the encryption/decryption of data is overwritten to data.
 *
 * @return 0 is encryption/decryption was successful, otherwise < 0.
 */
int hip_crypto_encrypted(void *data, const void *iv_orig, int alg, int len,
			 void* key, int direction)
{
        void *result = NULL;
	int err = -1;
	AES_KEY aes_key;
	des_key_schedule ks1, ks2, ks3;
	u8 secret_key1[8], secret_key2[8], secret_key3[8];
	u8 iv[20]; /* OpenSSL modifies the IV it is passed during the encryption/decryption */
        HIP_IFEL(!(result = malloc(len)), -1, "Out of memory\n");
	HIP_HEXDUMP("hip_crypto_encrypted encrypt data", data, len);
        
	HIP_DEBUG("d1\n");
	switch(alg) {
        case HIP_HIP_AES_SHA1:
	
     	HIP_DEBUG("d2\n");
		/* AES key must be 128, 192, or 256 bits in length */
		memcpy(iv, iv_orig, 16);
		if (direction == HIP_DIRECTION_ENCRYPT) {
 	HIP_DEBUG("d3\n");
			HIP_IFEL((err = AES_set_encrypt_key(key, 8 * hip_transform_key_length(alg), &aes_key)) != 0, err, 
				 "Unable to use calculated DH secret for AES key (%d)\n", err);
			HIP_HEXDUMP("AES key for OpenSSL: ", &aes_key, sizeof(unsigned long) * 4 * (AES_MAXNR + 1));
			HIP_HEXDUMP("AES IV: ", iv, 16);
			AES_cbc_encrypt(data, result, len, &aes_key, (unsigned char *)iv, AES_ENCRYPT);
		} else {
			HIP_IFEL((err = AES_set_decrypt_key(key, 8 * hip_transform_key_length(alg), &aes_key)) != 0, err, 
				 "Unable to use calculated DH secret for AES key (%d)\n", err);
			//HIP_HEXDUMP("AES key for OpenSSL: ", &aes_key, sizeof(unsigned long) * 4 * (AES_MAXNR + 1));
			//HIP_HEXDUMP("AES IV: ", iv, 16);
			AES_cbc_encrypt(data, result, len, &aes_key, (unsigned char *)iv, AES_DECRYPT);
		}
 		memcpy(data, result, len);
                break;

        case HIP_HIP_3DES_SHA1:
		memcpy(iv, iv_orig, 8);
		memcpy(&secret_key1, key, hip_transform_key_length(alg) / 3);
                memcpy(&secret_key2, key+8, hip_transform_key_length(alg) / 3);
                memcpy(&secret_key3, key+16, hip_transform_key_length(alg) / 3);

		des_set_odd_parity((des_cblock *)&secret_key1);
                des_set_odd_parity((des_cblock *)&secret_key2);
                des_set_odd_parity((des_cblock *)&secret_key3);

		HIP_IFEL( ((err = des_set_key_checked((
			(des_cblock *)&secret_key1), ks1)) != 0) ||
			  ((err = des_set_key_checked((
				  (des_cblock *)&secret_key2), ks2)) != 0) ||
			  ((err = des_set_key_checked((
				  (des_cblock *)&secret_key3), ks3)) != 0), err, 
			  "Unable to use calculated DH secret for 3DES key (%d)\n", err);
                des_ede3_cbc_encrypt(data, result, len,
				     ks1, ks2, ks3, (des_cblock*)iv, 
				     direction == HIP_DIRECTION_ENCRYPT ? DES_ENCRYPT : DES_DECRYPT);
		memcpy(data, result, len);
                break;

        case HIP_HIP_NULL_SHA1:
		HIP_DEBUG("Null encryption used.\n");
                break;

        default:
                HIP_IFEL(1, -EFAULT, "Attempted to use unknown CI (alg = %d)\n", alg);
        }

	
	_HIP_HEXDUMP("hip_crypto_encrypted decrypt data: ", result, len);	
	err = 0;

 out_err:
        if (result)
                free(result);

        return err;
}

void get_random_bytes(void *buf, int n)
{
	RAND_bytes(buf, n);
}

/*
 * function bn2bin_safe(BIGNUM *dest)
 *
 * BN_bin2bn() chops off the leading zero(es) of the BIGNUM,
 * so numbers end up being left shifted.
 * This fixes that by enforcing an expected destination length.
 */
int bn2bin_safe(const BIGNUM *a, unsigned char *to, int len)
{
        int padlen = len - BN_num_bytes(a);
        /* add leading zeroes when needed */
        if (padlen > 0)
                memset(to, 0, padlen);
        BN_bn2bin(a, &to[padlen]);
        /* return value from BN_bn2bin() may differ from length */
        return len;
}

/*
 * return 0 on success.
 */
int impl_dsa_sign(u8 *digest, u8 *private_key, u8 *signature)
{
	DSA_SIG *dsa_sig;
	DSA *dsa = NULL;
	int offset = 0, err = 1;
	int t = private_key[offset++];
	int len;

	HIP_IFEL(t > 8, 1, "Illegal DSA key\n");

	dsa = DSA_new();
	len = DSA_PRIV;
	dsa->q = BN_bin2bn(&private_key[offset], len, 0);
	offset += len;

	len = 64+8*t;
	dsa->p = BN_bin2bn(&private_key[offset], len, 0);
	offset += len;

	len = 64+8*t;
	dsa->g = BN_bin2bn(&private_key[offset], len, 0);
	offset += len;

	len = 64+8*t;
	dsa->pub_key = BN_bin2bn(&private_key[offset], len, 0);
	offset += len;

	len = DSA_PRIV;
	dsa->priv_key = BN_bin2bn(&private_key[offset], len, 0);
	offset += len;

	//HIP_DEBUG("DSA.q: %s\n", BN_bn2hex(dsa->q));
	//HIP_DEBUG("DSA.p: %s\n", BN_bn2hex(dsa->p));
	//HIP_DEBUG("DSA.g: %s\n", BN_bn2hex(dsa->g));
	//HIP_DEBUG("DSA.pubkey: %s\n", BN_bn2hex(dsa->pub_key));
	//HIP_DEBUG("DSA.privkey: %s\n", BN_bn2hex(dsa->priv_key));

	memset(signature, 0, HIP_DSA_SIG_SIZE);
	signature[0] = 8;

	//HIP_HEXDUMP("DSA signing digest", digest, SHA_DIGEST_LENGTH);

	/* calculate the DSA signature of the message hash */   
	dsa_sig = DSA_do_sign(digest, SHA_DIGEST_LENGTH, dsa);

	//HIP_DEBUG("DSAsig.r: %s\n", BN_bn2hex(dsa_sig->r));
	//HIP_DEBUG("DSAsig.s: %s\n", BN_bn2hex(dsa_sig->s));

	/* build signature from DSA_SIG struct */
	bn2bin_safe(dsa_sig->r, &signature[1], 20);
	bn2bin_safe(dsa_sig->s, &signature[21], 20);
	DSA_SIG_free(dsa_sig);
 	err = 0;

	_HIP_HEXDUMP("signature",signature,HIP_DSA_SIGNATURE_LEN);

 out_err:
	if (dsa)
		DSA_free(dsa);

	return err;
}

/*
 * @public_key pointer to host_id + 1
 * @signature pointer to hip_sig->signature
 */
int impl_dsa_verify(u8 *digest, u8 *public_key, u8 *signature)
{
	DSA_SIG dsa_sig;
	DSA *dsa;
	int offset = 0, err;
	u8 t = public_key[offset++];
	int key_len = 64 + (t * 8);

	/* Build the public key */
	dsa = DSA_new();
	/* get Q, P, G, and Y */
	dsa->q = BN_bin2bn(&public_key[offset], DSA_PRIV, 0);
	offset += DSA_PRIV;
	dsa->p = BN_bin2bn(&public_key[offset], key_len, 0);
	offset += key_len;
	dsa->g = BN_bin2bn(&public_key[offset], key_len, 0);
	offset += key_len;
	dsa->pub_key = BN_bin2bn(&public_key[offset], key_len, 0);

	//HIP_DEBUG("DSA.q: %s\n", BN_bn2hex(dsa->q));
	//HIP_DEBUG("DSA.p: %s\n", BN_bn2hex(dsa->p));
	//HIP_DEBUG("DSA.g: %s\n", BN_bn2hex(dsa->g));
	//HIP_DEBUG("DSA.pubkey: %s\n", BN_bn2hex(dsa->pub_key));

	/* build the DSA structure */
	dsa_sig.r = BN_bin2bn(&signature[1], 20, NULL);
	dsa_sig.s = BN_bin2bn(&signature[21], 20, NULL);

	//HIP_DEBUG("DSAsig.r: %s\n", BN_bn2hex(dsa_sig.r));
	//HIP_DEBUG("DSAsig.s: %s\n", BN_bn2hex(dsa_sig.s));

	//HIP_HEXDUMP("DSA verifying digest", digest, SHA_DIGEST_LENGTH);

	/* verify the DSA signature */
	err = DSA_do_verify(digest, SHA_DIGEST_LENGTH, &dsa_sig, dsa);
	BN_free(dsa_sig.r);
	BN_free(dsa_sig.s);
	DSA_free(dsa);
	HIP_DEBUG("DSA verify: %d\n", err);
	
	return err == 1 ? 0 : 1;
}

/*
 * return 0 on success.
 */
int impl_rsa_sign(u8 *digest, u8 *private_key, u8 *signature, int priv_klen)
{
	RSA *rsa;
	BN_CTX *ctx;
	u8 *data = private_key;
	int offset = 0;
	int len = data[offset++];
	int slice, err, res = 1;
	unsigned int sig_len;
	
	/* Build the private key */
	rsa = RSA_new();
	if (!rsa) {
		goto err;
	}

	rsa->e = BN_bin2bn(&data[offset], len, 0);
	offset += len;

        slice = (priv_klen - len) / 6;
        len = 2 * slice;
	rsa->n = BN_bin2bn(&data[offset], len, 0);
	offset += len;

        len = 2 * slice;
	rsa->d = BN_bin2bn(&data[offset], len, 0);
	offset += len;

        len = slice;
	rsa->p = BN_bin2bn(&data[offset], len, 0);
	offset += len;

        len = slice;
	rsa->q = BN_bin2bn(&data[offset], len, 0);
	offset += len;

	ctx = BN_CTX_new();
	if (!ctx) {
		goto err;
	}

	rsa->iqmp = BN_mod_inverse(NULL, rsa->p, rsa->q, ctx);
	if (!rsa->iqmp) {
		HIP_ERROR("Unable to invert.\n");
		goto err;
	}

	/* assuming RSA_sign() uses PKCS1 - RFC 3110/2437
	 * hash = SHA1 ( data )
	 * prefix = 30 21 30 09 06 05 2B 0E 03 02 1A 05 00 04 14 
	 * signature = ( 00 | FF* | 00 | prefix | hash) ** e (mod n)
	 */
	sig_len = RSA_size(rsa);
	memset(signature, 0, sig_len);
	err = RSA_sign(NID_sha1, digest, SHA_DIGEST_LENGTH, signature,
		       &sig_len, rsa);
	res = err == 0 ? 1 : 0;
	
	
	_HIP_DEBUG("***********RSA SIGNING ERROR*************\n");
	_HIP_DEBUG("Siglen %d,signature length %d,  err :%d\n",sig_len,strlen(signature),err);
	_HIP_DEBUG("***********RSA SIGNING ERROR*************\n");
	

	_HIP_HEXDUMP("signature",signature,HIP_RSA_SIGNATURE_LEN);
 err:
	if (rsa)
		RSA_free(rsa);
	if (ctx)
		BN_CTX_free(ctx);

	return res;
}

int impl_rsa_verify(u8 *digest, u8 *public_key, u8 *signature, int pub_klen)
{
	RSA *rsa;
	struct hip_sig *sig = (struct hip_sig *)(signature - 1);
	u8 *data = public_key;
	int offset = 0;
	int e_len, key_len, sig_len, err;

	e_len = data[offset++];
	if (e_len == 0) {
		e_len = (u16) data[offset];
		e_len = ntohs(e_len);
		offset += 2;
	}

	if (e_len > 512) { /* RFC 3110 limits this field to 4096 bits */
		HIP_ERROR("RSA HI has invalid exponent length of %u\n",
			  e_len);
		return(-1);
	}

	key_len = pub_klen - (e_len + ((e_len > 255) ? 3 : 1));
	

	/* Build the public key */
	rsa = RSA_new();
	rsa->e = BN_bin2bn(&data[offset], e_len, 0);
	offset += e_len;
	rsa->n = BN_bin2bn(&data[offset], key_len, 0);

	sig_len = ntohs(sig->length) - 1; /* exclude algorithm */

	//HIP_DEBUG("INSIDE impl_rsa_verfiy :: key_len=%d, sig_len= %d, sig->length = %d\n",key_len,sig_len,sig->length);
	/* verify the RSA signature */
	err = RSA_verify(NID_sha1, digest, SHA_DIGEST_LENGTH,
			 signature,RSA_size(rsa) , rsa);
	/*RSA_verify returns 1 if success.*/

	
	unsigned long e_code = ERR_get_error();
	ERR_load_crypto_strings();
	

		
	_HIP_DEBUG("***********RSA ERROR*************\n");
	_HIP_DEBUG("htons %d , RSA_size(rsa) = %d\n",htons(sig->length),RSA_size(rsa));
	char buf[200];
	_HIP_DEBUG("Signature length :%d\n",strlen(signature));
	ERR_error_string(e_code ,buf);
	//HIP_DEBUG("Signature that has to be verified: %s\n",sig->signature);
	_HIP_DEBUG("Error string :%s\n",buf);
	_HIP_DEBUG("LIB error :%s\n",ERR_lib_error_string(e_code));
	_HIP_DEBUG("func error :%s\n",ERR_func_error_string(e_code));
	_HIP_DEBUG("Reason error :%s\n",ERR_reason_error_string(e_code));
	_HIP_DEBUG("***********RSA ERROR*************\n");
	
	
	RSA_free(rsa);

	HIP_DEBUG("RSA verify: %d\n", err);

	return err == 1 ? 0 : 1;
}
int hip_gen_dh_shared_key(DH *dh, u8 *peer_key, size_t peer_len, u8 *dh_shared_key,
			  size_t outlen)
{
	BIGNUM *peer_pub_key = NULL;
	size_t len;
	int err;

	HIP_IFEL(!dh, -EINVAL, "No DH context\n");
	HIP_IFEL(!(peer_pub_key = BN_bin2bn(peer_key, peer_len, NULL)), -EINVAL, "Unable to read peer_key\n");
	HIP_IFEL((len = DH_size(dh)) > outlen, -EINVAL, "Output buffer too small. %d bytes required\n", len);
	err = DH_compute_key(dh_shared_key, peer_pub_key, dh);

 out_err:
	if (peer_pub_key) 
		BN_free(peer_pub_key);

	return err;
}

int hip_encode_dh_publickey(DH *dh, u8 *out, int outlen)
{	
	int len, err;
        HIP_IFEL(!dh, -EINVAL, "No Diffie Hellman context for DH tlv.\n");
        HIP_IFEL(outlen < (len = BN_num_bytes(dh->pub_key)), -EINVAL, 
		 "Output buffer too small. %d bytes required\n", len);

        err = bn2bin_safe(dh->pub_key, out, outlen);

 out_err:
	return err;
}

DH *hip_generate_dh_key(int group_id)
{
        int err;
	DH *dh;
        char rnd_seed[20];
        struct timeval time1;
        
        gettimeofday(&time1, NULL);
        sprintf(rnd_seed, "%x%x", (unsigned int) time1.tv_usec,
		(unsigned int) time1.tv_sec);
        RAND_seed(rnd_seed, sizeof(rnd_seed));
        
        dh = DH_new();
        dh->g = BN_new();
        dh->p = BN_new();
        /* Put prime corresponding to group_id into dh->p */
        BN_bin2bn(dhprime[group_id],
                  dhprime_len[group_id], dh->p);
        /* Put generator corresponding to group_id into dh->g */
        BN_set_word(dh->g, dhgen[group_id]);
        /* By not setting dh->priv_key, allow crypto lib to pick at random */
        if ((err = DH_generate_key(dh)) != 1) {
                HIP_ERROR("DH key generation failed (%d).\n", err);
                exit(1);
        }
        return dh;
}

void hip_free_dh(DH *dh)
{
	if (dh) {
		DH_free(dh);
	}
}

/**
 * hip_get_dh_size - determine the size for required to store DH shared secret
 * @param hip_dh_group_type the group type from DIFFIE_HELLMAN parameter
 *
 * @return 0 on failure, or the size for storing DH shared secret in bytes
 */
u16 hip_get_dh_size(u8 hip_dh_group_type) {
	u16 ret = -1;

	_HIP_DEBUG("dh_group_type=%u\n", hip_dh_group_type);
	if (hip_dh_group_type == 0) 
		HIP_ERROR("Trying to use reserved DH group type 0\n");
	else if (hip_dh_group_type > ARRAY_SIZE(dhprime_len))
		HIP_ERROR("Unknown/unsupported MODP group %d\n", hip_dh_group_type);
	else
		ret = dhprime_len[hip_dh_group_type];

	return ret;
}

int hip_init_cipher(void)
{
	int err = 0;
	u32 supported_groups;

	supported_groups = (1 << HIP_DH_OAKLEY_1 |
                            1 << HIP_DH_OAKLEY_5 |
			    1 << HIP_DH_384);

	HIP_DEBUG("Generating DH keys\n");
	hip_regen_dh_keys(supported_groups);

	return 1;
}

/**
 * create_dsa_key - generate DSA parameters and a new key pair
 * @param bits length of the prime
 *
 * The caller is responsible for freeing the allocated DSA key.
 *
 * @return the created DSA structure, otherwise NULL.
 *
 */
DSA *create_dsa_key(int bits) {
  DSA *dsa = NULL;
  int ok;

  if (bits < 1 || bits > HIP_MAX_DSA_KEY_LEN) {
    HIP_ERROR("create_dsa_key failed (illegal bits value %d)\n", bits);
    goto err_out;
  }

  dsa = DSA_generate_parameters(bits, NULL, 0, NULL, NULL, NULL, NULL);
  if (!dsa) {
    HIP_ERROR("create_dsa_key failed (DSA_generate_parameters): %s\n",
	     ERR_error_string(ERR_get_error(), NULL));
    goto err_out;
  }

  /* generate private and public keys */
  ok = DSA_generate_key(dsa);
  if (!ok) {
    HIP_ERROR("create_dsa_key failed (DSA_generate_key): %s\n",
	     ERR_error_string(ERR_get_error(), NULL));
    goto err_out;
  }

  return dsa;

 err_out:

  if (dsa)
    DSA_free(dsa);

  return NULL;
}

/**
 * create_rsa_key - generate RSA parameters and a new key pair
 * @param bits length of the prime
 *
 * The caller is responsible for freeing the allocated RSA key.
 *
 * @return the created RSA structure, otherwise NULL.
 *
 */
RSA *create_rsa_key(int bits) {
  RSA *rsa = NULL;
  int ok;

  if (bits < 1 || bits > HIP_MAX_RSA_KEY_LEN) {
    HIP_ERROR("create_rsa_key failed (illegal bits value %d)\n", bits);
    goto err_out;
  }

  /* generate private and public keys */
  rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL);
  if (!rsa) {
    HIP_ERROR("create_rsa_key failed (RSA_generate_key): %s\n",
	     ERR_error_string(ERR_get_error(), NULL));
    goto err_out;
  }

  return rsa;

 err_out:

  if (rsa)
    RSA_free(rsa);

  return NULL;
}

/* Note: public here means that you only have the public key,
   not the private */
int hip_any_key_to_hit(void *any_key, unsigned char *any_key_rr, int hit_type,
		       hip_hit_t *hit, int is_public, int is_dsa) {
  int err = 0, key_rr_len;
  unsigned char *key_rr = NULL;
  char hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];
  struct hip_host_id *host_id = NULL;
  RSA *rsa_key = (RSA *) any_key;
  DSA *dsa_key = (DSA *) any_key;

  memset(hostname, 0, HIP_HOST_ID_HOSTNAME_LEN_MAX);
  HIP_IFEL(gethostname(hostname, HIP_HOST_ID_HOSTNAME_LEN_MAX - 1), -1,
  	   "gethostname failed\n");

  if (is_dsa) {
    HIP_IFEL(((key_rr_len = dsa_to_dns_key_rr(dsa_key, &key_rr)) <= 0), -1,
	     "key_rr_len\n");
    HIP_IFEL(alloc_and_build_param_host_id_only(&host_id, key_rr, key_rr_len,
						HIP_HI_DSA, hostname), -1,
	     "alloc\n");
    if (is_public) {
      HIP_IFEL(hip_dsa_host_id_to_hit(host_id, hit, HIP_HIT_TYPE_HASH100),
	       -1, "conversion from host id to hit failed\n");
    } else {
      HIP_IFEL(hip_private_dsa_host_id_to_hit(host_id, hit,
					      HIP_HIT_TYPE_HASH100),
	       -1, "conversion from host id to hit failed\n");
    }
  } else /* rsa */ {
    HIP_IFEL(((key_rr_len = rsa_to_dns_key_rr(rsa_key, &key_rr)) <= 0), -1,
	     "key_rr_len\n");
    HIP_IFEL(alloc_and_build_param_host_id_only(&host_id, key_rr, key_rr_len,
						HIP_HI_RSA, hostname), -1,
	     "alloc\n");
    if (is_public) {
      HIP_IFEL(hip_rsa_host_id_to_hit(host_id, hit, HIP_HIT_TYPE_HASH100),
	       -1, "conversion from host id to hit failed\n");
    } else {
      HIP_IFEL(hip_private_rsa_host_id_to_hit(host_id, hit,
					      HIP_HIT_TYPE_HASH100),
	       -1, "conversion from host id to hit failed\n");
    }
  }

   HIP_DEBUG_HIT("hit", hit);
   HIP_DEBUG("hi is %s %s\n", (is_public ? "public" : "private"),
	     (is_dsa ? "dsa" : "rsa"));

 out_err:

  if (key_rr)
    HIP_FREE(key_rr);
  if (host_id)
    HIP_FREE(host_id);

  return err;
}

int hip_public_rsa_to_hit(RSA *rsa_key, unsigned char *rsa, int type,
			  struct in6_addr *hit) {
  return hip_any_key_to_hit(rsa_key, rsa, type, hit, 1, 0);
}

int hip_private_rsa_to_hit(RSA *rsa_key, unsigned char *rsa, int type,
			  struct in6_addr *hit) {
  return hip_any_key_to_hit(rsa_key, rsa, type, hit, 0, 0);
}

int hip_public_dsa_to_hit(DSA *dsa_key, unsigned char *dsa, int type,
			  struct in6_addr *hit) {
  return hip_any_key_to_hit(dsa_key, dsa, type, hit, 1, 1);
}

int hip_private_dsa_to_hit(DSA *dsa_key, unsigned char *dsa, int type,
			   struct in6_addr *hit) {
  return hip_any_key_to_hit(dsa_key, dsa, type, hit, 0, 1);
}


/**
 * dsa_to_dns_key_rr - create DNS KEY RR record from host DSA key
 * @param dsa the DSA structure from where the KEY RR record is to be created
 * @param dsa_key_rr where the resultin KEY RR is stored
 *
 * Caller must free dsa_key_rr when it is not used anymore.
 *
 * @return On successful operation, the length of the KEY RR buffer is
 * returned (greater than zero) and pointer to the buffer containing
 * DNS KEY RR is stored at dsa_key_rr. On error function returns negative
 * and sets dsa_key_rr to NULL.
 */
int dsa_to_dns_key_rr(DSA *dsa, unsigned char **dsa_key_rr) {
  int err = 0;
  int dsa_key_rr_len = -1;
  signed char t; /* in units of 8 bytes */
  unsigned char *p;
  unsigned char *bn_buf = NULL;
  int bn_buf_len;
  int bn2bin_len;

  HIP_ASSERT(dsa != NULL); /* should not happen */

  *dsa_key_rr = NULL;

  _HIP_DEBUG("numbytes p=%d\n", BN_num_bytes(dsa->p));
  _HIP_DEBUG("numbytes q=%d\n", BN_num_bytes(dsa->q));
  _HIP_DEBUG("numbytes g=%d\n", BN_num_bytes(dsa->g));
  _HIP_DEBUG("numbytes pubkey=%d\n", BN_num_bytes(dsa->pub_key)); // shouldn't this be NULL also?

  /* notice that these functions allocate memory */
  _HIP_DEBUG("p=%s\n", BN_bn2hex(dsa->p));
  _HIP_DEBUG("q=%s\n", BN_bn2hex(dsa->q));
  _HIP_DEBUG("g=%s\n", BN_bn2hex(dsa->g));
  _HIP_DEBUG("pubkey=%s\n", BN_bn2hex(dsa->pub_key));

  /* ***** is use of BN_num_bytes ok ? ***** */
  t = (BN_num_bytes(dsa->p) - 64) / 8;
  if (t < 0 || t > 8) {
    HIP_ERROR("t=%d < 0 || t > 8\n", t);
    err = -EINVAL;
    goto out_err;
  }
  _HIP_DEBUG("t=%d\n", t);

  /* RFC 2536 section 2 */
  /*
           Field     Size
           -----     ----
            T         1  octet
            Q        20  octets
            P        64 + T*8  octets
            G        64 + T*8  octets
            Y        64 + T*8  octets
	  [ X        20 optional octets (private key hack) ]
	
  */
  dsa_key_rr_len = 1 + 20 + 3 * (64 + t * 8);

  if (dsa->priv_key) {
    dsa_key_rr_len += 20; /* private key hack */
    _HIP_DEBUG("Private key included\n");
  } else {
    _HIP_DEBUG("No private key\n");
  }

  _HIP_DEBUG("dsa key rr len = %d\n", dsa_key_rr_len);
  *dsa_key_rr = malloc(dsa_key_rr_len);
  if (!*dsa_key_rr) {
    HIP_ERROR("malloc\n");
    err = -ENOMEM;
    goto out_err;
  }

  /* side-effect: does also padding for Q, P, G, and Y */
  memset(*dsa_key_rr, 0, dsa_key_rr_len);

  /* copy header */
  p = *dsa_key_rr;

  /* set T */
  memset(p, t, 1); // XX FIX: WTF MEMSET?
  p += 1;
  _HIP_HEXDUMP("DSA KEY RR after T:", *dsa_key_rr, p - *dsa_key_rr);

  /* minimum number of bytes needed to store P, G or Y */
  bn_buf_len = BN_num_bytes(dsa->p);
  if (bn_buf_len <= 0) {
    HIP_ERROR("bn_buf_len p <= 0\n");
    err = -EINVAL;
    goto out_err_free_rr;
  }

  bn_buf = malloc(bn_buf_len);
  if (!bn_buf) {
    HIP_ERROR("malloc\n");
    err = -ENOMEM;
    goto out_err_free_rr;
  }
  
  /* Q */
  bn2bin_len = bn2bin_safe(dsa->q, bn_buf, 20);
  _HIP_DEBUG("q len=%d\n", bn2bin_len);
  if (!bn2bin_len) {
    HIP_ERROR("bn2bin\n");
    err = -ENOMEM;
    goto out_err;
  }
  HIP_ASSERT(bn2bin_len == 20);
  memcpy(p, bn_buf, bn2bin_len);
  p += bn2bin_len;
  _HIP_HEXDUMP("DSA KEY RR after Q:", *dsa_key_rr, p-*dsa_key_rr);

  /* add given dsa_param to the *dsa_key_rr */
#define DSA_ADD_PGY_PARAM_TO_RR(dsa_param, t)            \
  bn2bin_len = bn2bin_safe(dsa_param, bn_buf, 64 + t*8); \
  _HIP_DEBUG("len=%d\n", bn2bin_len);                    \
  if (!bn2bin_len) {                                     \
    HIP_ERROR("bn2bin\n");                               \
    err = -ENOMEM;                                       \
    goto out_err_free_rr;                                \
  }                                                      \
  HIP_ASSERT(bn_buf_len-bn2bin_len >= 0);                \
  p += bn_buf_len-bn2bin_len; /* skip pad */             \
  memcpy(p, bn_buf, bn2bin_len);                         \
  p += bn2bin_len;

  /* padding + P */
  DSA_ADD_PGY_PARAM_TO_RR(dsa->p, t);
  _HIP_HEXDUMP("DSA KEY RR after P:", *dsa_key_rr, p-*dsa_key_rr);
  /* padding + G */
  DSA_ADD_PGY_PARAM_TO_RR(dsa->g, t);
  _HIP_HEXDUMP("DSA KEY RR after G:", *dsa_key_rr, p-*dsa_key_rr);
  /* padding + Y */
  DSA_ADD_PGY_PARAM_TO_RR(dsa->pub_key, t);
  _HIP_HEXDUMP("DSA KEY RR after Y:", *dsa_key_rr, p-*dsa_key_rr);
  /* padding + X */

#undef DSA_ADD_PGY_PARAM_TO_RR


  if(dsa->priv_key){
    bn2bin_len = bn2bin_safe(dsa->priv_key, bn_buf, 20);
    memcpy(p,bn_buf,bn2bin_len);
    
    p += bn2bin_len;
    _HIP_HEXDUMP("DSA KEY RR after X:", *dsa_key_rr, p-*dsa_key_rr);

  }

  goto out_err;

 out_err_free_rr:
  if (*dsa_key_rr)
    free(*dsa_key_rr);

 out_err:
  if (bn_buf)
    free(bn_buf);
  return dsa_key_rr_len;
}


/**
 * rsa_to_dns_key_rr - This is a new version of the function above. This function 
 *                     assumes that RSA given as a parameter is always public (Laura/10.4.2006)
                       Creates DNS KEY RR record from host RSA public key
 * @param rsa the RSA structure from where the KEY RR record is to be created
 * @param rsa_key_rr where the resultin KEY RR is stored
 *
 * Caller must free rsa_key_rr when it is not used anymore.
 *
 * @return On successful operation, the length of the KEY RR buffer is
 * returned (greater than zero) and pointer to the buffer containing
 * DNS KEY RR is stored at rsa_key_rr. On error function returns negative
 * and sets rsa_key_rr to NULL.
 */
int rsa_to_dns_key_rr(RSA *rsa, unsigned char **rsa_key_rr) {
  int err = 0, len;
  int rsa_key_rr_len = -1;
  signed char t; // in units of 8 bytes
  unsigned char *p;
  int bn2bin_len;
  unsigned char *c;
  int public = -1;
  
  HIP_ASSERT(rsa != NULL); // should not happen
  
  *rsa_key_rr = NULL;
  
  HIP_ASSERT(BN_num_bytes(rsa->e) < 255); // is this correct?
  
  //let's check if the RSA key is public or private
  //private exponent is NULL in public keys
  if(rsa->d == NULL){ 
    public = 1;
  
    // see RFC 2537
  
    //FIXME there may be something funny
    rsa_key_rr_len = 4; // 4 four bytes for flags, protocol and algorithm // XX CHECK: LAURA
    rsa_key_rr_len += 1; // public key exponent length 
    rsa_key_rr_len += BN_num_bytes(rsa->e); // public key exponent (3 bytes)
    rsa_key_rr_len += BN_num_bytes(rsa->n); // public key modulus (128 bytes)
    
  } else{
    public = 0;
    rsa_key_rr_len = 1 + BN_num_bytes(rsa->e) + BN_num_bytes(rsa->n) +  
      BN_num_bytes(rsa->d) + BN_num_bytes(rsa->p) + BN_num_bytes(rsa->q);
    
  }
  *rsa_key_rr = malloc(rsa_key_rr_len);
  if (!*rsa_key_rr) {
    HIP_ERROR("malloc\n");
    err = -ENOMEM;
    goto out_err;
  }

  memset(*rsa_key_rr, 0, rsa_key_rr_len);

  c = *rsa_key_rr;
  *c = (unsigned char) BN_num_bytes(rsa->e);
  c++; // = e_length 

  len = bn2bin_safe(rsa->e, c, 3);
  c += len;

  len = bn2bin_safe(rsa->n, c, 128);
  c += len;  

  if(!public){
    len = bn2bin_safe(rsa->d, c, 128);
    c += len;
    
    len = bn2bin_safe(rsa->p, c, 64);
    c += len;
    
    len = bn2bin_safe(rsa->q, c, 64);
    c += len;
  }
  
  rsa_key_rr_len = c - *rsa_key_rr;

 out_err:

  return rsa_key_rr_len;
}

/**
 * save_dsa_private_key - save host DSA keys to disk
 * @param filenamebase the filename base where DSA key should be saved
 * @param dsa the DSA key structure
 *
 * The DSA keys from dsa are saved in PEM format, public key to file
 * filenamebase.pub, private key to file filenamebase and DSA parameters to
 * file filenamebase.params. If any of the files cannot be saved, all
 * files are deleted.
 *
 * XX FIXME: change filenamebase to filename! There is no need for a
 * filenamebase!!!
 *
 * @return 0 if all files were saved successfully, or non-zero if an error
 * occurred.
 */
int save_dsa_private_key(const char *filenamebase, DSA *dsa) {
  int err = 0;
  char *pubfilename;
  int pubfilename_len;
  FILE *fp;

  if (!filenamebase) {
    HIP_ERROR("NULL filenamebase\n");
    return 1;
  }

  pubfilename_len =
    strlen(filenamebase) + strlen(DEFAULT_PUB_FILE_SUFFIX) + 1;
  pubfilename = malloc(pubfilename_len);
  if (!pubfilename) {
    HIP_ERROR("malloc(%d) failed\n", pubfilename_len);
    goto out_err;
  }

  /* check retval */
  snprintf(pubfilename, pubfilename_len, "%s%s", filenamebase,
	   DEFAULT_PUB_FILE_SUFFIX);

  HIP_INFO("Saving DSA keys to: pub='%s' priv='%s'\n", pubfilename,
	   filenamebase);
  HIP_INFO("Saving host DSA pubkey=%s\n", BN_bn2hex(dsa->pub_key));
  HIP_INFO("Saving host DSA privkey=%s\n", BN_bn2hex(dsa->priv_key));
  HIP_INFO("Saving host DSA p=%s\n", BN_bn2hex(dsa->p));
  HIP_INFO("Saving host DSA q=%s\n", BN_bn2hex(dsa->q));
  HIP_INFO("Saving host DSA g=%s\n", BN_bn2hex(dsa->g));

  /* rewrite using PEM_write_PKCS8PrivateKey */

  fp = fopen(pubfilename, "wb" /* mode */);
  if (!fp) {
    HIP_ERROR("Couldn't open public key file %s for writing\n", filenamebase);
    goto out_err;
  }

  err = PEM_write_DSA_PUBKEY(fp, dsa);
  if (!err) {
    HIP_ERROR("Write failed for %s\n", pubfilename);
    fclose(fp); /* add error check */
    goto out_err_pub;
  }
  fclose(fp); /* add error check */

  fp = fopen(filenamebase, "wb" /* mode */);
  if (!fp) {
    HIP_ERROR("Couldn't open private key file %s for writing\n", filenamebase);
    goto out_err_pub;
  }

  err = PEM_write_DSAPrivateKey(fp, dsa, NULL, NULL, 0, NULL, NULL);
  if (!err) {
    HIP_ERROR("Write failed for %s\n", filenamebase);
    fclose(fp); /* add error check */
    goto out_err_priv;
  }
  fclose(fp); /* add error check */

  free(pubfilename);

  return 0;

 out_err_priv:
   unlink(filenamebase); /* add error check */
 out_err_pub:
   unlink(pubfilename); /* add error check */

   free(pubfilename);
 out_err:
  return 1;
}

/**
 * save_rsa_private_key - save host RSA keys to disk
 * @param filenamebase the filename base where RSA key should be saved
 * @param rsa the RSA key structure
 *
 * The RSA keys from rsa are saved in PEM format, public key to file
 * filenamebase.pub, private key to file filenamebase and RSA
 * parameters to file filenamebase.params. If any of the files cannot
 * be saved, all files are deleted.
 *
 * XX FIXME: change filenamebase to filename! There is no need for a
 * filenamebase!!!
 *
 * @return 0 if all files were saved successfully, or non-zero if an
 * error occurred.
 */
int save_rsa_private_key(const char *filenamebase, RSA *rsa) {
  int err = 0;
  char *pubfilename;
  int pubfilename_len;
  FILE *fp;

  if (!filenamebase) {
    HIP_ERROR("NULL filenamebase\n");
    return 1;
  }

  pubfilename_len =
    strlen(filenamebase) + strlen(DEFAULT_PUB_FILE_SUFFIX) + 1;
  pubfilename = malloc(pubfilename_len);
  if (!pubfilename) {
    HIP_ERROR("malloc(%d) failed\n", pubfilename_len);
    goto out_err;
  }

  /* check retval */
  snprintf(pubfilename, pubfilename_len, "%s%s", filenamebase,
	   DEFAULT_PUB_FILE_SUFFIX);

  HIP_INFO("Saving RSA keys to: pub='%s' priv='%s'\n", pubfilename,
	   filenamebase);
  HIP_INFO("Saving host RSA n=%s\n", BN_bn2hex(rsa->n));
  HIP_INFO("Saving host RSA e=%s\n", BN_bn2hex(rsa->e));
  HIP_INFO("Saving host RSA d=%s\n", BN_bn2hex(rsa->d));
  HIP_INFO("Saving host RSA p=%s\n", BN_bn2hex(rsa->p));
  HIP_INFO("Saving host RSA q=%s\n", BN_bn2hex(rsa->q));

  /* rewrite using PEM_write_PKCS8PrivateKey */

  fp = fopen(pubfilename, "wb" /* mode */);
  if (!fp) {
    HIP_ERROR("Couldn't open public key file %s for writing\n",
	      filenamebase);
    goto out_err;
  }

  err = PEM_write_RSA_PUBKEY(fp, rsa);
  if (!err) {
    HIP_ERROR("Write failed for %s\n", pubfilename);
    fclose(fp); /* add error check */
    goto out_err_pub;
  }
  fclose(fp); /* add error check */

  fp = fopen(filenamebase, "wb" /* mode */);
  if (!fp) {
    HIP_ERROR("Couldn't open private key file %s for writing\n",
	      filenamebase);
    goto out_err_pub;
  }

  err = PEM_write_RSAPrivateKey(fp, rsa, NULL, NULL, 0, NULL, NULL);
  if (!err) {
    HIP_ERROR("Write failed for %s\n", filenamebase);
    fclose(fp); /* add error check */
    goto out_err_priv;
  }
  fclose(fp); /* add error check */

  free(pubfilename);

  return 0;

 out_err_priv:
   unlink(filenamebase); /* add error check */
 out_err_pub:
   unlink(pubfilename); /* add error check */

   free(pubfilename);
 out_err:
  return 1;
}



/**
 * load_dsa_private_key - load host DSA private keys from disk
 * @param filenamebase the file name base of the host DSA key
 * @param dsa Pointer to the DSA key structure.
 *
 * Loads DSA public and private keys from the given files, public key
 * from file filenamebase.pub and private key from file filenamebase. DSA
 * struct will be allocated dynamically and it is the responsibility
 * of the caller to free it with DSA_free.
 *
 * XX FIXME: change filenamebase to filename! There is no need for a
 * filenamebase!!!
 *
 * @return On success *dsa contains the RSA structure. On failure
 * *dsa contins NULL if the key could not be loaded (not in PEM format
 * or file not found, etc).
 */
int load_dsa_private_key(const char *filenamebase, DSA **dsa) {
  char *pubfilename = NULL;
  int pubfilename_len;
  char *paramsfilename = NULL;
  int paramsfilename_len;
  FILE *fp = NULL;
  int err = 0;

  *dsa = NULL;

  if (!filenamebase) {
    HIP_ERROR("NULL filename\n");
    err = -ENOENT;
    goto out_err;
  }

  fp = fopen(filenamebase, "rb");
  if (!fp) {
    HIP_ERROR("Could not open public key file %s for reading\n", filenamebase);
    err = -ENOMEM;
    goto out_err;
  }

  *dsa = PEM_read_DSAPrivateKey(fp, NULL, NULL, NULL);
  if (!*dsa) {
    HIP_ERROR("Read failed for %s\n", filenamebase);
    err = -EINVAL;
    goto out_err;
  }
  _HIP_INFO("Loaded host DSA pubkey=%s\n", BN_bn2hex((*dsa)->pub_key));
  _HIP_INFO("Loaded host DSA privkey=%s\n", BN_bn2hex((*dsa)->priv_key));
  _HIP_INFO("Loaded host DSA p=%s\n", BN_bn2hex((*dsa)->p));
  _HIP_INFO("Loaded host DSA q=%s\n", BN_bn2hex((*dsa)->q));
  _HIP_INFO("Loaded host DSA g=%s\n", BN_bn2hex((*dsa)->g));

 out_err:

  if (fp)
    err = fclose(fp);
  if (err && *dsa) {
    /* maybe useless */
    DSA_free(*dsa);
    *dsa = NULL;
  }

  return err;
}

/**
 * load_rsa_private_key - load host RSA private keys from disk
 * @param filenamebase the file name base of the host RSA key
 * @param rsa Pointer to the RSA key structure.
 *
 * Loads RSA public and private keys from the given files, public key
 * from file filenamebase.pub and private key from file filenamebase. RSA
 * struct will be allocated dynamically and it is the responsibility
 * of the caller to free it with RSA_free.
 *
 * XX FIXME: change filenamebase to filename! There is no need for a
 * filenamebase!!!
 *
 * @return On success *rsa contains the RSA structure. On failure
 * *rsa contains NULL if the key could not be loaded (not in PEM
 * format or file not found, etc).
 */
int load_rsa_private_key(const char *filenamebase, RSA **rsa) {
  char *pubfilename = NULL;
  int pubfilename_len;
  char *paramsfilename = NULL;
  int paramsfilename_len;
  FILE *fp = NULL;
  int err = 0;

  *rsa = NULL;

  if (!filenamebase) {
    HIP_ERROR("NULL filename\n");
    err = -ENOENT;
    goto out_err;
  }

  fp = fopen(filenamebase, "rb");
  if (!fp) {
    HIP_ERROR("Couldn't open public key file %s for reading\n", filenamebase);
    err = -ENOMEM;
    goto out_err;
  }

  *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
  if (!*rsa) {
    HIP_ERROR("Read failed for %s\n", filenamebase);
    err = -EINVAL;
    goto out_err;
  }
  _HIP_INFO("Loaded host RSA n=%s\n", BN_bn2hex((*rsa)->n));
  _HIP_INFO("Loaded host RSA e=%s\n", BN_bn2hex((*rsa)->e));
  _HIP_INFO("Loaded host RSA d=%s\n", BN_bn2hex((*rsa)->d));
  _HIP_INFO("Loaded host RSA p=%s\n", BN_bn2hex((*rsa)->p));
  _HIP_INFO("Loaded host RSA q=%s\n", BN_bn2hex((*rsa)->q));

 out_err:

  if (fp)
    err = fclose(fp);
  if (err && *rsa) {
    /* maybe useless */
    RSA_free(*rsa);
    *rsa = NULL;
  }

  return err;
}

/**
 * load_dsa_public_key - load host DSA public keys from disk
 * @param filename the file name of the host DSA key
 * @param dsa the DSA 
 *
 * Loads DSA public key from the given file.
 * The DSA struct will be allocated dynamically and it is the responsibility
 * of the caller to free it with DSA_free.
 *
 * @return NULL if the key could not be loaded (not in PEM format or file
 * not found, etc).
 */
int load_dsa_public_key(const char *filename, DSA **dsa) {
  DSA *dsa_tmp = NULL;
  FILE *fp = NULL;
  int err = 0;

  _HIP_DEBUG("load_dsa_public_key called\n");

  *dsa = NULL;

  if (!filename) {
    HIP_ERROR("NULL filename %s\n", filename);
    err = -ENOENT;
    goto out_err;
  }

  /* optimize as in load_rsa_private_key */
  *dsa = DSA_new();
  if (!*dsa) {
    HIP_ERROR("!dsa\n");
    err = -ENOMEM;
    goto out_err;
  }
  dsa_tmp = DSA_new();
  if (!dsa_tmp) {
    HIP_ERROR("!dsa_tmp\n");
    err = -ENOMEM;
    goto out_err;
  }

  fp = fopen(filename, "rb");
  if (!fp) {
    HIP_ERROR("Couldn't open public key file %s for reading\n", filename);
    err = -ENOENT; // XX FIX: USE ERRNO
    goto out_err;
  }

  dsa_tmp = PEM_read_DSA_PUBKEY(fp, NULL, NULL, NULL);
  if (!dsa_tmp) {
    HIP_ERROR("Read failed for %s\n", filename);
    err = -EINVAL; // XX FIX: USE ERRNO
    goto out_err;
  }

  (*dsa)->pub_key = BN_dup(dsa_tmp->pub_key);
  (*dsa)->p = BN_dup(dsa_tmp->p);
  (*dsa)->q = BN_dup(dsa_tmp->q);
  (*dsa)->g = BN_dup(dsa_tmp->g);
  if (!(*dsa)->p || !(*dsa)->q || !(*dsa)->g || !(*dsa)->pub_key) {
    HIP_ERROR("BN_copy\n");
    err = -EINVAL; // XX FIX: USE ERRNO
    goto out_err;
  }

  _HIP_INFO("Loaded host DSA pubkey=%s\n", BN_bn2hex((*dsa)->pub_key));
  _HIP_INFO("Loaded host DSA p=%s\n", BN_bn2hex((*dsa)->p));
  _HIP_INFO("Loaded host DSA q=%s\n", BN_bn2hex((*dsa)->q));
  _HIP_INFO("Loaded host DSA g=%s\n", BN_bn2hex((*dsa)->g));

 out_err:
  if (err && *dsa)
    DSA_free(*dsa);
  if (dsa_tmp)
    DSA_free(dsa_tmp);
  if (fp)
    err = fclose(fp);

  return err;
}

/**
 * load_rsa_public_key - load host RSA public keys from disk
 * @param filename the file name of the host RSA key
 * @param rsa the RSA 
 *
 * Loads RSA public key from the given file.
 * The RSA struct will be allocated dynamically and it is the responsibility
 * of the caller to free it with RSA_free.
 *
 * @return NULL if the key could not be loaded (not in PEM format or file
 * not found, etc).
 */
int load_rsa_public_key(const char *filename, RSA **rsa) {
  RSA *rsa_tmp = NULL;
  FILE *fp = NULL;
  int err = 0;

  *rsa = NULL;

  _HIP_DEBUG("load_rsa_public_key called\n");

  if (!filename) {
    HIP_ERROR("NULL filename\n");
    err = -ENOENT;
    goto out_err;
  }

  /* optimize as in load_rsa_private_key */
  *rsa = RSA_new();
  if (!*rsa) {
    HIP_ERROR("!rsa\n");
    err = -ENOMEM;
    goto out_err;
  }
  rsa_tmp = RSA_new();
  if (!rsa_tmp) {
    HIP_ERROR("!rsa_tmp\n");
    err = -ENOMEM;
    goto out_err;
  }

  fp = fopen(filename, "rb");
  if (!fp) {
    HIP_ERROR("Couldn't open public key file %s for reading\n", filename);
    err = -ENOENT; // XX FIX: USE ERRNO
    goto out_err;
  }

  rsa_tmp = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
  if (!rsa_tmp) {
    HIP_ERROR("Read failed for %s\n", filename);
    err = -EINVAL; // XX FIX: USE ERRNO
    goto out_err;
  }

  (*rsa)->n = BN_dup(rsa_tmp->n);
  (*rsa)->e = BN_dup(rsa_tmp->e);
  (*rsa)->dmp1 = BN_dup(rsa_tmp->dmp1);
  (*rsa)->dmq1 = BN_dup(rsa_tmp->dmq1);
  (*rsa)->iqmp = BN_dup(rsa_tmp->iqmp);
  if (!(*rsa)->n || !(*rsa)->e) {
    HIP_ERROR("BN_copy\n");
    err = -EINVAL; // XX FIX: USE ERRNO
    goto out_err;
  }

  _HIP_INFO("Loaded host RSA n=%s\n", BN_bn2hex((*rsa)->n));
  _HIP_INFO("Loaded host RSA e=%s\n", BN_bn2hex((*rsa)->e));

 out_err:
  if (err && *rsa)
    RSA_free(*rsa);
  if (rsa_tmp)
    RSA_free(rsa_tmp);
  if (fp)
    err = fclose(fp);

  return err;
}

int dsa_to_hip_endpoint(DSA *dsa, struct endpoint_hip **endpoint,
			se_hip_flags_t endpoint_flags, const char *hostname)
{
  int err = 0;
  unsigned char *dsa_key_rr = NULL;
  int dsa_key_rr_len;
  struct endpoint_hip endpoint_hdr;

  _HIP_DEBUG("dsa_to_hip_endpoint called\n");

  dsa_key_rr_len = dsa_to_dns_key_rr(dsa, &dsa_key_rr);
  if (dsa_key_rr_len <= 0) {
    HIP_ERROR("dsa_key_rr_len <= 0\n");
    err = -ENOMEM;
    goto out_err;
  }

  /* build just an endpoint header to see how much memory is needed for the
     actual endpoint */
  hip_build_endpoint_hdr(&endpoint_hdr, hostname, endpoint_flags,
			 HIP_HI_DSA, dsa_key_rr_len);

  *endpoint = malloc(endpoint_hdr.length);
  if (!(*endpoint)) {
    err = -ENOMEM;
    goto out_err;
  }
  memset(*endpoint, 0, endpoint_hdr.length);

  _HIP_DEBUG("Allocated %d bytes for endpoint\n", endpoint_hdr.length);
  hip_build_endpoint(*endpoint, &endpoint_hdr, hostname,
		     dsa_key_rr, dsa_key_rr_len);
  _HIP_HEXDUMP("endpoint contains: ", *endpoint, endpoint_hdr.length);

 out_err:

  if (dsa_key_rr)
    free(dsa_key_rr);

  return err;
}

int rsa_to_hip_endpoint(RSA *rsa, struct endpoint_hip **endpoint,
			se_hip_flags_t endpoint_flags, const char *hostname)
{
  int err = 0;
  unsigned char *rsa_key_rr = NULL;
  int rsa_key_rr_len;
  struct endpoint_hip endpoint_hdr;

  HIP_DEBUG("rsa_to_hip_endpoint called\n");

  rsa_key_rr_len = rsa_to_dns_key_rr(rsa, &rsa_key_rr);
  if (rsa_key_rr_len <= 0) {
    HIP_ERROR("rsa_key_rr_len <= 0\n");
    err = -ENOMEM;
    goto out_err;
  }

  /* build just an endpoint header to see how much memory is needed for the
     actual endpoint */
  hip_build_endpoint_hdr(&endpoint_hdr, hostname, endpoint_flags,
			 HIP_HI_RSA, rsa_key_rr_len);

    *endpoint = malloc(endpoint_hdr.length);
  if (!(*endpoint)) {
    err = -ENOMEM;
    goto out_err;
  }
  memset(*endpoint, 0, endpoint_hdr.length);

  _HIP_DEBUG("Allocated %d bytes for endpoint\n", endpoint_hdr.length);

  hip_build_endpoint(*endpoint, &endpoint_hdr, hostname,
		     rsa_key_rr, rsa_key_rr_len);
			   
  _HIP_HEXDUMP("endpoint contains: ", *endpoint, endpoint_hdr.length);

 out_err:

  if (rsa_key_rr)
    free(rsa_key_rr);

  return err;
}

int alloc_and_set_host_id_param_hdr(struct hip_host_id **host_id,
				    unsigned int key_rr_len,
				    uint8_t algo,
				    const char *hostname)
{
  int err = 0;
  struct hip_host_id host_id_hdr;

  hip_build_param_host_id_hdr(&host_id_hdr, hostname,
			      key_rr_len, algo);

  *host_id = malloc(hip_get_param_total_len(&host_id_hdr));
  if (!host_id) {
    err = -ENOMEM;
  }  

  memcpy(*host_id, &host_id_hdr, sizeof(host_id_hdr));

  return err;
}

int alloc_and_build_param_host_id_only(struct hip_host_id **host_id,
				       unsigned char *key_rr, int key_rr_len,
				       int algo, char *hostname) {
  int err = 0;

  HIP_IFEL(alloc_and_set_host_id_param_hdr(host_id, key_rr_len, algo,
					   hostname), -1, "alloc\n");
  hip_build_param_host_id_only(*host_id, key_rr, "hostname");

 out_err:
  if (err && *host_id) {
    *host_id = NULL;
    HIP_FREE(host_id);
  }

  return err;
}
