#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cipher.h"

int main(int argc, char* argv[]) {
    if (argc < 3) {
        perror("usage: ./cipher <data> <key>");
        exit(1);
    }

    if (!check_key(argv[2], strlen(argv[2]))) {
        perror("key must be 16 bits (2 len)");
        exit(2);
    }

    mykey_t* key = store_key(argv[2]);

    input_t* in = store(argv[1], strlen(argv[1]));

    printf("------PADDED INPUT------\n");

    for (int c = 0; c < in->len; c++) {
        printf("0x%02lx ", in->data[c]);
    }
    // printf("%s\n", in->data);
    printf("\n");

    printf("------KEY------\n");

    printf("0x%04lx\n", key->k);

    printf("------BLOCKS------\n");

    block_t** block_array = to_blocks(in);
    size_t n_blocks = in->len / 4;

    for (int i = 0; i < n_blocks; i++) {
        printf("blk#%d: 0x%08lx\n", i, block_array[i]->blk);
    }

    
    printf("------FROM BLOCKS------\n");

    output_t* out = store_output(block_array, n_blocks);

    for (int i = 0; i < out->len; i++) {
        printf("%c", out->data[i]);
    }
    printf("\n");
    

    printf("------FEISTEL------\n");

    feistel(block_array, n_blocks, key);

    for (int i = 0; i < n_blocks; i++) {
        printf("blk#%d: 0x%08lx\n", i, block_array[i]->blk);
    }

    // key_reset(key);

    printf("------CIPHERED------\n");

    free(out);
    out = store_output(block_array, n_blocks);

    for (int i = 0; i < out->len; i++) {
        printf("%c", out->data[i]);
    }
    printf("\n");

    // key_reset(key);

    printf("------I_FEISTEL------\n");

    i_feistel(block_array, n_blocks, key);
    
    for (int i = 0; i < n_blocks; i++) {
        printf("blk#%d: 0x%08lx\n", i, block_array[i]->blk);
    }
    
    printf("------DECIPHERED------\n");

    free(out);
    out = store_output(block_array, n_blocks);

    for (int i = 0; i < out->len; i++) {
        printf("%c", out->data[i]);
    }
    printf("\n");

    free_blocks(block_array, n_blocks);
    free(key);
    free(out);
    free(in);
    
    return 0;
}
