#ifndef CIPHER_H
#define CIPHER_H

#include <stddef.h>
#include <stdbool.h>

/*
 * Structure to define a block of data
 *
 * Fields:
 * 		blk: 32 bits (unsigned long) 
 */
typedef struct block {
	unsigned long blk;
} block_t;

/* 
 * Structure to define the data being processed
 * 
 * Fields:
 * 		data: a pointer to a region in memory where it will reside
 * 		len: length of data - will always be a multiple of 32 (size of block)
 */
typedef struct input {
	char* data;
	size_t len;
} input_t;

/* 
 * Structure to define the output of processed data
 * 
 * Fields:
 * 		data: a pointer to a region in memory where it will reside
 * 		len: length of output - will always be a multiple of 32 (size of block)
 */
typedef struct output {
	char* data;
	size_t len;
} output_t;

/* 
 * Structure to define the key
 * This will make it easier to perform bitwise operations
 * during key scheduling
 * 
 * Fields:
 * 		k: the numeric value of the parsed key
 */
typedef struct key {
	unsigned short k;
} mykey_t;

/* 
 * Function to check whether the provided input respects 32 bit block size
 * 
 * Parameters:
 * 		input: data to process
 * 		original_length: original length of provided data
 * 
 * Returns:
 * 		char: number of chars needed to pad
 */
char check_input(char* input, size_t original_length);

/*
 * Function to check whether the provided key is 64 bits
 * 
 * Parameters:
 * 		key: charray (32 bits => len should be 8)
 * 
 * Returns:
 * 		bool: is it valid?
 */
bool check_key(char* key, size_t original_length);

/* 
 * Function to store provided input into a structure 'input_t'
 * ASSUME PKCS#7
 * 
 * Parameter:
 * 		input: data to process
 * 
 * Returns:
 * 		input_t*: newly created structure with data
 */
input_t* store(char* input, size_t original_length);

/*
 * Function to store processed ciphertext into a structure 'output_t'
 * 
 * Parameters:
 * 		block_array: ciphered data in blocks
 * 		n_blocks: n of blocks to read from
 * 
 * Returns:
 * 		output_t*: newly created structure with ciphertext 
 */
output_t* store_output(block_t** block_array, size_t n_blks);

/* 
 * Function to store the key in a numerical format. Len is known to be 16
 *
 * Parameters:
 * 		key: key string
 * 
 * Returns:
 * 		key_t*: newly created structure with key
 */
mykey_t* store_key(char* key);

/* 
 * Function to create an array of blocks out of the padded input
 *
 * Parameter:
 * 		input: padded data (input)
 * 
 * Returns:
 * 		block_t**: array of 32 bit blocks
 */
block_t** to_blocks(input_t* input);

/*
 * Function to free blocks from a previously created block array
 * 
 * Parameter:
 * 		block_array: blocks
 * 
 * Returns: void 
 */
void free_blocks(block_t** block_array, size_t n_blks);

/* 
 * Function to perform feistel network on block array 
 * 
 * Parameter:
 * 		block_array: blocks
 * 		n_blks: length of block array
 * 		key: key
 * 
 * Returns: void
 */
void feistel(block_t** block_array, size_t n_blks, mykey_t* key);

/* 
 * Function to perform backwards (inverse) feistel network on block array
 * 
 * Parameters:
 * 		block_array: blocks
 * 		n_blks: length of block array
 * 		key: key
 * 
 * Returns: void
 */
void i_feistel(block_t** block_array, size_t n_blks, mykey_t* key);

/* 
 * Round Function
 * Splits 16 bit input into two 8 bit halves, L and R,
 * S-boxes the right one,
 * and the left half is xored with the latter.
 * Then, some permutations are done.
 * 
 * After this, both sides are swapped before returning.
 *
 * Parameter:
 * 		sublk: sub blok (16 bit)
 * 
 * Returns:
 * 		unsigned short: 16 bits
 */
unsigned short round_function(unsigned short sublk, mykey_t* key);

/*
 * Function to reset key after round function
 * 
 * Parameter:
 * 		key: key
 * 
 * Returns: void
 */
void key_reset(mykey_t* key);

#endif

