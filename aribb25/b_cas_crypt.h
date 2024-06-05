/**
 * @file b_cas_crypt.h
 *
 *	original code from http://pastebin.com/xsL2j1ti
 */
#pragma once
#include "portable.h"

extern void bcas_decrypt(uint8_t *out, const uint8_t *in, uint64_t key, uint8_t protocol);
