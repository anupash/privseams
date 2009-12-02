/**
 * Hash tree functions for packet authentication and
 * packet signatures
 *
 * Description:
 *
 * Authors:
 *   - Tobias Heer <heer@tobobox.de> 2008
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#ifndef HASH_TREE_H_
#define HASH_TREE_H_

#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <inttypes.h>

/* arguments for the generator functionms */
typedef struct htree_gen_args
{
	int index;
} htree_gen_args_t;

/** leaf generator function pointer
 *
 * NOTE: if you need additional arguments here, add them to the gen_args struct
 */
typedef int (*htree_leaf_gen_t) (const unsigned char *data, const int data_length,
		const unsigned char *secret, const int secret_length,
		unsigned char *dst_buffer, const htree_gen_args_t *gen_args);

/** node generator function pointer
 *
 * NOTE: if you need additional arguments here, add them to the gen_args struct
 */
typedef int (*htree_node_gen_t) (const unsigned char *left_node, const unsigned char *right_node,
		const int node_length, unsigned char *dst_buffer,
		const htree_gen_args_t *gen_args);

typedef struct hash_tree
{
	// data variables
	int leaf_set_size;	 /* maximum number of data blocks to be stored in the tree */
	int num_data_blocks; /* number of data blocks to be verified with the tree */
	int max_data_length; /* max length for a single leaf element */
	unsigned char *data; /* array containing the data to be validated with the tree */
	int secret_length;	/* length of the secret */
	unsigned char *secrets; /* individual secrets to be revealed with each data block */

	struct hash_tree *link_tree;
	int hierarchy_level;

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


double log_x(const int base, const double value);
hash_tree_t* htree_init(const int num_data_blocks, const int max_data_length, const int node_length,
		const int secret_length, hash_tree_t *link_tree, const int hierarchy_level);
void htree_free(hash_tree_t *tree);
int htree_add_data(hash_tree_t *tree, const unsigned char *data, const int data_length);
int htree_add_random_data(hash_tree_t *tree, const int num_random_blocks);
int htree_add_secret(hash_tree_t *tree, const unsigned char *secret, const int secret_length, const int secret_index);
int htree_add_random_secrets(hash_tree_t *tree);
int htree_calc_nodes(hash_tree_t *tree, const htree_leaf_gen_t leaf_gen,
		const htree_node_gen_t node_gen, const htree_gen_args_t *gen_args);
int htree_get_num_remaining(const hash_tree_t *tree);
int htree_has_more_data(const hash_tree_t *tree);
int htree_get_next_data_offset(hash_tree_t *tree);
unsigned char * htree_get_branch(const hash_tree_t *tree, const int data_index, unsigned char * nodes,
		int *branch_length);
const unsigned char* htree_get_data(const hash_tree_t *tree, const int data_index,
		int *data_length);
const unsigned char* htree_get_secret(const hash_tree_t *tree, const int secret_index,
		int *secret_length);
const unsigned char* htree_get_root(const hash_tree_t *tree, int *root_length);
int htree_verify_branch(const unsigned char *root, const int root_length,
		const unsigned char *branch_nodes, const uint32_t branch_length,
		const unsigned char *verify_data, const int data_length, const uint32_t data_index,
		const unsigned char *secret, const int secret_length,
		const htree_leaf_gen_t leaf_gen, const htree_node_gen_t node_gen,
		const htree_gen_args_t *gen_args);
int htree_leaf_generator(const unsigned char *data, const int data_length,
		const unsigned char *secret, const int secret_length,
		unsigned char *dst_buffer, const htree_gen_args_t *gen_args);
int htree_node_generator(const unsigned char *left_node, const unsigned char *right_node,
		const int node_length, unsigned char *dst_buffer, const htree_gen_args_t *gen_args);
void htree_print_data(const hash_tree_t *tree);
void htree_print_nodes(const hash_tree_t *tree);

#endif /* HASH_TREE_H_ */
