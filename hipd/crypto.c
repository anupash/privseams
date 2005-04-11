#include "crypto.h"

struct crypto_tfm *impl_sha1; /* XX FIX: FILL THIS STRUCTURE */

time_t load_time; /* XX FIX: INITIALIZE THIS */

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

void crypto_digest_digest(struct crypto_tfm *tfm, char *src_buf, int ignore,
			  char *dst_buf) {
	// i2/r1 processing
	HIP_ERROR("Not implemented.\n");
	exit(1); /* XX FIXME */
}

/**
 * hip_build_digest - calculate a digest over given data
 * @type: the type of digest, e.g. "sha1"
 * @in: the beginning of the data to be digested
 * @in_len: the length of data to be digested in octets
 * @out: the digest
 *
 * @out should be long enough to hold the digest. This cannot be
 * checked!
 *
 * Returns: 0 on success, otherwise < 0.
 */
int hip_build_digest(const int type, const void *in, int in_len, void *out) {
	// i2/r2
	HIP_ERROR("Not implemented.\n");
	exit(1); /* XX FIXME */
	return 1;
}

/**
 * hip_build_digest_repeat - Calculate digest repeatedly
 * @dgst: Digest transform
 * @sg: Valid scatterlist array
 * @nsg: Number of scatterlists in the @sg array.
 * @out: Output buffer. Should contain enough bytes for the digest.
 * 
 * Use this function instead of the one above when you need to do repeated
 * calculations *IN THE SAME MEMORY SPACE (SIZE _AND_ ADDRESS)*
 * This is an optimization for cookie solving. There we do a lots of digests
 * in the same memory block and its size is constant.
 * So instead of calling N times hip_map_virtual_to_pages() the caller maps
 * once and all the digest iterations use the same pages.
 * This improves the speed greatly.
 *
 * Returns 0 always. The digest is written to @out.
*/
int hip_build_digest_repeat(struct crypto_tfm *dgst, char *data, int ignore,
			    void *out)
{
	// puzzle solving
	HIP_ERROR("Not implemented!\n");
	exit(1); /* XX FIXME */
	return 1;
}

/**
 * hip_write_hmac - calculate hmac
 * @type: Type (digest algorithm) of HMAC
 * @key: Pointer to the key used for HMAC
 * @in: Input buffer pointer
 * @in_len: Length of buffer
 * @out: Output buffer pointer. For SHA1-HMAC this is 160bits
 *
 * Returns true, if ok.
 */
int hip_write_hmac(int type, void *key, void *in, int in_len, void *out)
{
	switch(type) {
        case HIP_DIGEST_SHA1_HMAC:
                HMAC(   EVP_sha1(), 
                        get_key(hip_a, HIP_INTEGRITY, FALSE),
                        auth_key_len(hip_a->hip_transform),
                        data, location,
                        hmac_md, &hmac_md_len  );
                break;
        case HIP_DIGEST_MD5_HMAC:
                HMAC(   EVP_md5(), 
                        get_key(hip_a, HIP_INTEGRITY, FALSE),
                        auth_key_len(hip_a->hip_transform),
                        data, location,
                        hmac_md, &hmac_md_len  );
                break;
        default:
                HIP_ERROR("Unknown HMAC type 0x%x\n",type);
                return 0;
        }

	return 1;
}

/**
 * hip_crypto_encrypted - encrypt/decrypt data
 * @data: data to be encrypted/decrypted
 * @iv: initialization vector
 * @enc_alg: encryption algorithm to use
 * @enc_len: length of @data
 * @enc_key: encryption/decryption key to use
 * @direction: flag for selecting encryption/decryption
 *
 * @direction is HIP_DIRECTION_ENCRYPT if @data is to be encrypted
 * or HIP_DIRECTION_DECRYPT if @data is to be decrypted.
 *
 * The result of the encryption/decryption of @data is overwritten to @data.
 *
 * Returns: 0 is encryption/decryption was successful, otherwise < 0.
 */
int hip_crypto_encrypted(void *data, const void *iv, int enc_alg, int enc_len,
			 void* enc_key, int direction)
{
	// i2 creation/processing
	HIP_ERROR("Not implemeted.\n");
	exit(1); /* XX FIXME */
	return 1;
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
static int bn2bin_safe(const BIGNUM *a, unsigned char *to, int len)
{
        int padlen = len - BN_num_bytes(a);
        /* add leading zeroes when needed */
        if (padlen > 0)
                memset(to, 0, padlen);
        BN_bn2bin(a, &to[padlen]);
        /* return value from BN_bn2bin() may differ from length */
        return(len);
}

/*
 * return 0 on success.
 */
int hip_dsa_sign(u8 *digest, u8 *private_key, u8 *signature)
{
	DSA_SIG *dsa_sig;
	DSA *dsa;
	int offset = 0, err = 1;
	int t = private_key[offset++];
	int len;

	if (t > 8) {
                HIP_ERROR("Illegal DSA key\n");
                goto err;
        }

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

	memset(signature, 0, HIP_DSA_SIG_SIZE);
	signature[0] = 8;
	/* calculate the DSA signature of the message hash */   
	dsa_sig = DSA_do_sign(digest, SHA_DIGEST_LENGTH, dsa);
	/* build signature from DSA_SIG struct */
	bn2bin_safe(dsa_sig->r, &signature[1], 20);
	bn2bin_safe(dsa_sig->s, &signature[21], 20);
	DSA_SIG_free(dsa_sig);
 	err = 0;

 err:
	if (dsa)
		DSA_free(dsa);

	return err;
}

/*
 * @public_key pointer to host_id + 1
 * @signature pointer to tlv_start + 1
 */
int hip_dsa_verify(u8 *digest, u8 *public_key, u8 *signature)
{
	DSA_SIG dsa_sig;
	DSA *dsa;
	struct hip_sig *sig = (struct hip_sig *)(signature - 1);
	int offset = 0;
	int err;
	u8 t = *public_key;
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

	/* build the DSA structure */
	dsa_sig.r = BN_bin2bn(&sig->signature[1], 20, NULL);
	dsa_sig.s = BN_bin2bn(&sig->signature[21], 20, NULL);
	/* verify the DSA signature */
	err = DSA_do_verify(digest, SHA_DIGEST_LENGTH, &dsa_sig, dsa);
	BN_free(dsa_sig.r);
	BN_free(dsa_sig.s);
	DSA_free(dsa);
	
	return err == 0 ? 1 : 0;
}

/*
 * return 0 on success.
 */
int hip_rsa_sign(u8 *digest, u8 *private_key, u8 *signature, int priv_klen)
{
	RSA *rsa;
	BN_CTX *ctx;
	u8 *data = private_key;
	int offset = 0;
	int len = data[offset++];
	int slice, sig_len, err, res = 1;
	
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

 err:
	if (rsa)
		RSA_free(rsa);
	if (ctx)
		BN_CTX_free(ctx);

	return res;
}

int hip_rsa_verify(u8 *digest, u8 *public_key, u8 *signature, int pub_klen)
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

	/* verify the RSA signature */
	err = RSA_verify(NID_sha1, digest, SHA_DIGEST_LENGTH,
			 sig->signature, sig_len, rsa);

	RSA_free(rsa);

	return err == 0 ? 1 : 0;
}

int hip_gen_dh_shared_key(DH *dh, u8 *peer_key, size_t peer_len, u8 *dh_shared_key,
			  size_t outlen)
{
	BIGNUM peer_pub_key;
	size_t len;

	if (!dh) {
		HIP_ERROR("No DH context\n");
		return -EINVAL;
	}

	if (!BN_bin2bn(peer_key, len, &peer_pub_key)) {
		HIP_ERROR("Unable to read peer_key\n");
		return -EINVAL;
	}

	if ((len = DH_size(dh)) > outlen) {
		HIP_ERROR("Output buffer too small. %d bytes required\n", len);
		return -EINVAL;
	}

	return DH_compute_key(dh_shared_key, &peer_pub_key, dh);
}

int hip_encode_dh_publickey(DH *dh, u8 *out, int outlen)
{	
	int len;
        if (!dh) {
                HIP_ERROR("No Diffie Hellman context for DH tlv.\n");
		return -EINVAL;
        }

        if (outlen < (len = BN_num_bytes(dh->pub_key))) {
                HIP_ERROR("Output buffer too small. %d bytes required\n", len);
                return -EINVAL;
        }

        return BN_bn2bin(dh->pub_key, out);
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
 * @hip_dh_group_type: the group type from DIFFIE_HELLMAN parameter
 *
 * Returns: 0 on failure, or the size for storing DH shared secret in bytes
 */
u16 hip_get_dh_size(u8 hip_dh_group_type) {
	u16 ret = -1;

	_HIP_DEBUG("dh_group_type=%u\n", hip_dh_group_type);
	if (hip_dh_group_type == 0) 
		HIP_ERROR("Trying to use reserved DH group type 0\n");
	else if (hip_dh_group_type == HIP_DH_384)
		HIP_ERROR("draft-09: Group ID 1 does not exist yet\n");
	else if (hip_dh_group_type > ARRAY_SIZE(dhprime_len))
		HIP_ERROR("Unknown/unsupported MODP group %d\n", hip_dh_group_type);
	else
		ret = dhprime_len[hip_dh_group_type];

	return ret + 1;

}
