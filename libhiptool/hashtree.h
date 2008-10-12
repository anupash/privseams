/*
 *  hashtree.h
 *
 *  Created by Tobias Heer on 21.04.08.
 *  Copyright 2008 Tobias Heer. All rights reserved.
 *
 */

#ifndef HASH_TREE_H_
#define HASH_TREE_H_

//#include <string.h>         // memcpy, size_t
//#include <stdint.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

typedef struct htree_gen_args
{
	int index;
} htree_gen_args_t;

/* leaf generator function pointer
 *
 * @note if you need more arguments here, add them to the gen_args struct
 */
typedef int (*htree_leaf_gen_t) (unsigned char *data, unsigned char *secret, int data_length,
							   unsigned char *dst_buffer, htree_gen_args_t *gen_args);

typedef int (*htree_node_gen_t) (unsigned char *left_node, unsigned char *right_node,
							   unsigned char *dst_buffer, int node_length,
							   htree_gen_args_t *gen_args);

typedef struct hash_tree
{
	// data variables
	int num_data_blocks; /* number of data blocks to be verified with the tree */
	int max_data_length; /* max length for a single leaf element */
	unsigned char *data; /* array containing the data to be validated with the tree */
	unsigned char *secrets; /* individual secrets to be revealed with each data block */

	// tree elements variables
	int node_length; /* length of a single node element */
	unsigned char *nodes; /* array containing the nodes of the tree */
	unsigned char *root; /* the root of the tree -> points into nodes-array */

	// management variables
	int depth; /* depth of the tree */
	int data_position; /* index of the next free leaf */
	int is_open; /* can one enter new entries?
					This is only true if the nodes have not been
					computed yet. */
} hash_tree_t;

#if 0
typedef struct ht_root
{
	char* node;

	int treeDepth;
	int treeSize;
	int nodeSize;
} ht_root_t;
#endif


hash_tree_t* htree_init(int num_data_blocks, int max_data_length, int node_length);
void htree_free(hash_tree_t *tree);
int htree_add_data(hash_tree_t *tree, char *data, size_t data_length);
int htree_add_random_data(hash_tree_t *tree, int num_random_blocks);
int htree_add_random_secrets(hash_tree_t *tree);
int htree_calc_nodes(hash_tree_t *tree, htree_leaf_gen_t leaf_gen,
		htree_node_gen_t node_gen, htree_gen_args_t *gen_args);
int htree_get_next_data_offset(hash_tree_t *tree);
unsigned char* htree_get_branch(hash_tree_t *tree, int data_index,
		int *branch_length);
unsigned char* htree_get_data(hash_tree_t *tree, int data_index,
		int *data_length);
unsigned char* htree_get_secret(hash_tree_t *tree, int data_index,
		int *secret_length);
unsigned char* htree_get_root(hash_tree_t *tree, int *root_length);
int htree_verify_branch(unsigned char *root, unsigned char *branch_nodes, int num_nodes,
		int node_length, unsigned char *verify_data, unsigned char * secret,
		int data_length, int data_index, htree_leaf_gen_t leaf_gen,
		htree_node_gen_t node_gen, htree_gen_args_t *gen_args);
int htree_leaf_generator(unsigned char *data, unsigned char *secret, int data_length,
		unsigned char *dst_buffer, htree_gen_args_t *gen_args);
int htree_node_generator(unsigned char *left_node, unsigned char *right_node,
		   unsigned char *dst_buffer, int node_length, htree_gen_args_t *gen_args);
void htree_print_data(hash_tree_t *tree);
void htree_print_nodes(hash_tree_t *tree);



#if 0
hash_tree_t* ht_createTree(int treeSize, int packetSize, int hashSize);

hash_tree_t* ht_createAckTree(size_t treeSize, size_t secretSize, size_t nodeSize);

ht_root_t* ht_createRoot(char* buffer, size_t nodeSize, size_t treeSize);

int ht_addLeaf(hash_tree_t* tree, char* data, size_t len);

int ht_computeNodes(hash_tree_t* tree,
				 ht_leafGeneratorPtr generateLeaf,
				 ht_nodeGeneratorPtr generateNode);

ht_err ht_sigLeafGenerator(unsigned char* leaf,
					 uint16_t index,
					 unsigned char* destinationBuffer,
					 size_t leafSize,
					 void* generatorArgs);


ht_err ht_ackLeafGenerator(unsigned char* leaf,
					 uint16_t index,
					 unsigned char* destinationBuffer,
					 size_t leafSize,
					 void* generatorArgs);


ht_err ht_sigNodeGenerator(unsigned char* leftNode,
						unsigned char* rightNode,
						uint16_t index,
						unsigned char* destinationBuffer,
						size_t nodeSize,
						void* args);

int ht_getRoot(hash_tree_t* tree, char* buffer, int len);

void ht_printLeaves(hash_tree_t* tree);

void ht_printNodes(hash_tree_t* tree);

int ht_getUpTree(hash_tree_t* tree, int leafIndex, char* buffer, size_t len);

int ht_verifyBuffer(ht_root_t* root,
				 int nodeIndex,
				 char* data,
				 int dataLen,
				 char* nodes,
				 int nodeLen);
#endif

#endif /* HASH_TREE_H_ */
