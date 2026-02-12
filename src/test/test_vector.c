/* Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license. */

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "test_vector.h"
#include <stdio.h>
#include <string.h>


int TvecLoad(const char *filename, TestVector *vectors, int max_count, int *count)
{
	FILE *fp;
	TvecHeader header;
	int i;
	
	*count = 0;
	
	fp = fopen(filename, "rb");
	if (!fp) {
		return -1;  // File not found
	}
	
	// Read header
	if (fread(&header, sizeof(TvecHeader), 1, fp) != 1) {
		fclose(fp);
		return -2;  // Read error
	}
	
	// Validate header
	if (header.magic != TVEC_MAGIC) {
		fclose(fp);
		return -3;  // Invalid magic
	}
	
	if (header.version != TVEC_VERSION) {
		fclose(fp);
		return -4;  // Unsupported version
	}
	
	if (header.count > (uint32_t)max_count) {
		fclose(fp);
		return -5;  // Too many vectors
	}
	
	// Read entries
	for (i = 0; i < (int)header.count; i++) {
		TvecEntryHeader entry;
		TestVector *v = &vectors[i];
		
		// Read entry header
		if (fread(&entry, sizeof(TvecEntryHeader), 1, fp) != 1) {
			fclose(fp);
			return -6;  // Read error
		}
		
		// Validate lengths
		if (entry.key_len > TVEC_MAX_KEY_LEN ||
		    entry.iv_len > TVEC_MAX_IV_LEN ||
		    entry.plaintext_len > TVEC_MAX_DATA_LEN ||
		    entry.ciphertext_len > TVEC_MAX_DATA_LEN ||
		    entry.aad_len > TVEC_MAX_AAD_LEN ||
		    entry.tag_len > TVEC_MAX_TAG_LEN) {
			fclose(fp);
			return -7;  // Invalid length
		}
		
		// Copy metadata
		v->algorithm = entry.algorithm;
		v->mode = entry.mode;
		v->key_len = entry.key_len;
		v->iv_len = entry.iv_len;
		v->plaintext_len = entry.plaintext_len;
		v->ciphertext_len = entry.ciphertext_len;
		v->aad_len = entry.aad_len;
		v->tag_len = entry.tag_len;
		
		// Read variable data
		if (entry.key_len > 0 && fread(v->key, 1, entry.key_len, fp) != entry.key_len) {
			fclose(fp);
			return -8;
		}
		
		if (entry.iv_len > 0 && fread(v->iv, 1, entry.iv_len, fp) != entry.iv_len) {
			fclose(fp);
			return -8;
		}
		
		if (entry.plaintext_len > 0 && fread(v->plaintext, 1, entry.plaintext_len, fp) != entry.plaintext_len) {
			fclose(fp);
			return -8;
		}
		
		if (entry.ciphertext_len > 0 && fread(v->ciphertext, 1, entry.ciphertext_len, fp) != entry.ciphertext_len) {
			fclose(fp);
			return -8;
		}
		
		if (entry.aad_len > 0 && fread(v->aad, 1, entry.aad_len, fp) != entry.aad_len) {
			fclose(fp);
			return -8;
		}
		
		if (entry.tag_len > 0 && fread(v->tag, 1, entry.tag_len, fp) != entry.tag_len) {
			fclose(fp);
			return -8;
		}
	}
	
	*count = (int)header.count;
	fclose(fp);
	return 0;
}

void TvecFree(TestVector *vectors, int count)
{
	// Currently no dynamic allocation, so nothing to free
	// This function exists for API consistency and future extensibility
	(void)vectors;
	(void)count;
}
