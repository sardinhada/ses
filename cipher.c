#include <stdlib.h>

#include "cipher.h"

#define N_ROUNDS 2

/*
 * S-box
 */
unsigned char s_box[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5b, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6b, 0x10, 0x0c, 0x22, 0x55, 0x45, 0x18, 0xf2,
    0x02, 0x62, 0x8d, 0x93, 0x4a, 0x62, 0x3d, 0x91,
    0xd2, 0x75, 0x4c, 0x60, 0x16, 0x0d, 0xa4, 0x90,
    0x5f, 0xb6, 0x9d, 0x87, 0x40, 0x87, 0xa8, 0x7c,
    0xa7, 0x0f, 0x4e, 0x71, 0x2b, 0x1e, 0xc9, 0x50,
    0xc2, 0x0c, 0x5f, 0x54, 0x2d, 0x43, 0x92, 0xb9,
    0x7d, 0x4b, 0x3f, 0x6f, 0x5b, 0x68, 0xd5, 0xe9,
    0xd0, 0x11, 0x9b, 0x63, 0x30, 0x5e, 0x86, 0x12,
    0xd4, 0xd6, 0x48, 0xe3, 0xb7, 0x8e, 0x24, 0x88,
    0x9e, 0x7c, 0x8f, 0x69, 0xa8, 0xf1, 0x6f, 0x6b,
    0x8a, 0x79, 0xd5, 0xd7, 0x0c, 0x5a, 0x0a, 0x29,
    0x71, 0x45, 0x1f, 0x7e, 0x93, 0x15, 0x49, 0xb8,
    0x4d, 0x8b, 0xe7, 0x31, 0x12, 0x9a, 0x7e, 0x4f,
    0x22, 0x60, 0x45, 0x8e, 0x0a, 0xb1, 0x6e, 0xf0,
    0x43, 0x7c, 0x67, 0x55, 0x6f, 0x12, 0x71, 0xd1,
    0x62, 0x0d, 0x68, 0x5f, 0x96, 0xe3, 0x9c, 0x4c,
    0x20, 0x2e, 0x72, 0x8b, 0x90, 0x51, 0x80, 0xc1,
    0x31, 0xb3, 0xf7, 0xe9, 0xe7, 0xb5, 0x8f, 0x68,
    0xd8, 0x67, 0xe5, 0x4e, 0x5a, 0x8c, 0x9a, 0xb1,
    0x4a, 0x76, 0xc4, 0x84, 0x77, 0x69, 0x96, 0xa7,
    0x20, 0x9b, 0xf4, 0xe0, 0x9e, 0xe8, 0x3f, 0x4b,
};

char check_input(char* input, size_t original_length) {
    return (char)(original_length % 4);
}

input_t* store(char* input, size_t original_length) {
    char n_of_pads = (char) 4 - check_input(input, original_length);

    size_t new_len;
    if (n_of_pads == 4) {
        new_len = original_length;
    } else {
        new_len = original_length + n_of_pads;
    }

    char* data = (char*) malloc(sizeof(char) * new_len);

    int i;
    // populates new data array
    for (i = 0; i < original_length; i++) {
        data[i] = input[i];
    }

    // pads new data array with PKCS#7
    for (; i < new_len; i++) {
        data[i] = n_of_pads;
    }
    
    input_t* in = (input_t*) malloc(sizeof(input_t));
    in->data = data;
    in->len = new_len;

    return in;
}

bool check_key(char* key, size_t original_length) {
    bool result = original_length == 2 ? true : false;
    return result;
}

output_t* store_output(block_t** block_array, size_t n_blocks) {
    size_t cipher_len = n_blocks * 8; // in chars (8bits of char = 32bits of ul / 4bits of char)

    output_t* out = (output_t*) malloc(sizeof(output_t));
    out->data = (char*) malloc(sizeof(char) * cipher_len);
    out->len = cipher_len;

    for (int i = 0; i < n_blocks; i++) {
        for (int j = 0; j < 4; j++) {
            out->data[i * 4 + j] = (char)((block_array[i]->blk >> (j * 8)) & 0xFF);
        }
    }

    return out;
}

mykey_t* store_key(char* key) {
    mykey_t* key_real = (mykey_t*) malloc(sizeof(mykey_t));
    key_real->k = 0;
    key_real->k = ((unsigned short) key[0] << 8) | (unsigned short) key[1];
    /*
    for (int i = 0; i < 4; i++) {
        key_real->k <<= (12 - (4 * (i % 4)));
        key_real->k |= key[i];
        // key_real->k |= (unsigned short)(key[i] << (12 - (4 * (i % 2))));
    }
    */

    return key_real;
}

block_t** to_blocks(input_t* input) {
    size_t n_blocks = input->len / 4;
    block_t** block_array = (block_t**) malloc(sizeof(block_t*) * n_blocks);

    for (int i = 0; i < n_blocks; i++) {
        block_t* new_block = (block_t*) malloc(sizeof(block_t));
        new_block->blk = 0;

        /*
        for (int j = i * 4; j < (i * 4) + 4; j++) {
            new_block->blk |= ((unsigned long) input->data[j] << (24 - (8 * (j % 4))));
        }
        */

        new_block->blk |= ((unsigned long) input->data[(i * 4) + 0] << 0);
        new_block->blk |= ((unsigned long) input->data[(i * 4) + 1] << 8);
        new_block->blk |= ((unsigned long) input->data[(i * 4) + 2] << 16);
        new_block->blk |= ((unsigned long) input->data[(i * 4) + 3] << 24);

        block_array[i] = new_block;
    }

    return block_array;
}

void free_blocks(block_t** block_array, size_t n_blks) {
    for (int i = 0; i < n_blks; i++) {
        free(block_array[i]);
    }
    free(block_array);
}

void feistel(block_t** block_array, size_t n_blks, mykey_t* key) {
    if (n_blks < 2)
        return;

    unsigned short left_0, left_1, right_0, right_1;
    // real shit
    for (int i = 0; i < n_blks; i++) {
        right_0 = block_array[i]->blk & 0xFFFF;
        left_0 = (block_array[i]->blk >> 16) & 0xFFFF;

        for (int j = 0; j < N_ROUNDS; j++) {
            left_1 = right_0;
            right_1 = left_0 ^ round_function(right_0, key);

            left_0 = left_1;
            right_0 = right_1;
        }

        block_array[i]->blk = ((unsigned long) left_1 << 16) | right_1;
    }
}

void i_feistel(block_t** block_array, size_t n_blks, mykey_t* key) {
    if (n_blks < 2)
        return;

    unsigned short left_0, left_1, right_0, right_1;

    for (int i = n_blks - 1; i > -1; i--) {
        right_0 = block_array[i]->blk & 0xFFFF;
        left_0 = (block_array[i]->blk >> 16) & 0xFFFF;

        for (int j = 0; j < N_ROUNDS; j++) {
            right_1 = left_0;
            left_1 = right_0 ^ round_function(left_0, key);
            
            left_0 = left_1;
            right_0 = right_1;
        }

        block_array[i]->blk = ((unsigned long) left_1 << 16) | right_1;
    }
}

unsigned short round_function(unsigned short sublk, mykey_t* key) {
    unsigned char right, left;
    right = sublk & 0xFF;
    left = (sublk >> 8) & 0xFF;

    // calculate subkey by SHIFTING IT LEFT
    unsigned short rotated_key;
    rotated_key = (key->k << 3) | (key->k >> (16 - 3));

    unsigned short moddadded_key;
    moddadded_key = (sublk + key->k) & 0xFFFF;

    // s-box the block
    right = s_box[right];
    left = s_box[left];

    // sublk = ((unsigned short) right << 8) | left;

    return (unsigned short)(sublk ^ moddadded_key ^ rotated_key);
}

void key_reset(mykey_t* key) {
    for (int i = 0; i < N_ROUNDS; i++) {
        key->k >>= 1;
    }
}