/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @file
 * API for Hash trees
 *
 * @brief API for Hash trees
 */

#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include "common.h"
#include "debug.h"
#include "ife.h"
#include "hashtree.h"

/** calculates the logarithm for a given base
 *
 * @param       base the base of the logarithm
 * @param       value value for which the log should be computed
 * return       logarithm of value to base
 */
double log_x(const int base, const double value)
{
    return log(value) / log(base);
}

/** adds a secret to the tree.
 *
 * @param       tree pointer to the tree
 * @param   secret the secret to be added
 * @param       secret_length length of the secret
 * @param       secret_index position of the secret in the leaf set
 * @return      always 0
 */
static int htree_add_secret(struct hash_tree *tree,
                            const unsigned char *secret,
                            const int secret_length,
                            const int secret_index)
{
    HIP_ASSERT(tree != NULL);
    HIP_ASSERT(secret != NULL);
    HIP_ASSERT(secret_length == tree->secret_length);
    HIP_ASSERT(secret_index >= 0 && secret_index < tree->num_data_blocks);
    HIP_ASSERT(tree->is_open > 0);

    memcpy(&tree->secrets[secret_index * secret_length], secret, secret_length);

    return 0;
}

/** creates an empty hash tree.
 *
 * @param       num_data_blocks number of leaf node
 * @param       max_data_length the maximum data length hashed in a leaf node
 * @param       node_length the length of a hash value
 * @param       secret_length length of the eventual secrets
 * @param       link_tree the link tree in case of HHL-based linking
 * @param       hierarchy_level the hierarchy level of the created hash tree
 * @return      pointer to the inited tree, NULL in case of an error.
 */
struct hash_tree *htree_init(const int num_data_blocks,
                             const int max_data_length,
                             const int node_length,
                             const int secret_length,
                             struct hash_tree *link_tree,
                             const int hierarchy_level)
{
    struct hash_tree *tree       = NULL;
    int               tmp_length = 0, err = 0, i;
    double            loga       = 0.0;

    HIP_ASSERT(num_data_blocks > 0);
    HIP_ASSERT(max_data_length > 0);
    HIP_ASSERT(node_length > 0);


    // allocate the memory for the tree
    HIP_IFEL(!(tree = calloc(1, sizeof(struct hash_tree))),
             -1, "failed to allocate memory\n");

    // check here whether leaf_set_size is a power of 2 and compute correct value if it is not
    loga = log_x(2, num_data_blocks);
    if (num_data_blocks == 1) {
        tree->leaf_set_size = 2;
    } else if (floor(loga) != ceil(loga)) {
        tree->leaf_set_size = pow(2, ceil(loga));
    } else {
        tree->leaf_set_size = num_data_blocks;
    }
    HIP_DEBUG("num_data_blocks: %i\n", num_data_blocks);
    HIP_DEBUG("tree->leaf_set_size: %i\n", tree->leaf_set_size);

    HIP_IFEL(!(tree->data = malloc(max_data_length * tree->leaf_set_size)),
             -1, "failed to allocate memory\n");
    // a binary tree with n leafs has got 2n-1 total nodes
    HIP_IFEL(!(tree->nodes = malloc(node_length * tree->leaf_set_size * 2)),
             -1, "failed to allocate memory\n");

    // if link_tree is set, overwrite secret_length
    if (link_tree) {
        HIP_DEBUG("link_tree set\n");

        tmp_length = link_tree->node_length;
    } else {
        tmp_length = secret_length;
    }

    tree->is_open         = 1;
    tree->data_position   = 0;
    tree->num_data_blocks = num_data_blocks;
    tree->max_data_length = max_data_length;
    tree->node_length     = node_length;
    tree->secret_length   = tmp_length;
    tree->depth           = ceil(log_x(2, tree->leaf_set_size));
    // set the link tree
    tree->link_tree       = link_tree;
    tree->hierarchy_level = hierarchy_level;

    HIP_DEBUG("tree->depth: %i\n", tree->depth);

    tree->root = NULL;

    // now we can init the secret array
    if (secret_length > 0) {
        HIP_IFEL(!(tree->secrets = malloc(secret_length * tree->leaf_set_size)),
                 -1, "failed to allocate memory\n");

        if (link_tree) {
            // add the root as secret for each leaf
            for (i = 0; i < num_data_blocks; i++) {
                HIP_IFEL(htree_add_secret(tree, link_tree->root, secret_length, i),
                         -1,
                         "failed to add linking root as secrets\n");
            }
        }
    }

out_err:
    if (err) {
        htree_free(tree);
    }

    return tree;
}

/** frees the hash tree
 *
 * @param       tree the hash tree to be freed
 */
void htree_free(struct hash_tree *tree)
{
    if (tree) {
        htree_free(tree->link_tree);

        free(tree->nodes);
        free(tree->data);
        free(tree->secrets);

        free(tree);
    }

    tree = NULL;
}

/** adds a data item to the tree.
 *
 * @param       tree pointer to the tree
 * @param   data data to be added
 * @param       data_length length of the data item
 * @return      always 0
 */
int htree_add_data(struct hash_tree *tree,
                   const unsigned char *data,
                   const int data_length)
{
    int err = 0;

    HIP_ASSERT(tree != NULL);
    HIP_ASSERT(data != NULL);
    HIP_ASSERT(data_length > 0 && data_length <= tree->max_data_length);
    HIP_ASSERT(tree->is_open > 0);
    HIP_ASSERT(tree->data_position >= 0 && tree->data_position < tree->num_data_blocks);

    /* add the leaf the leaf-array
     *
     * @note data_length < tree->max_data_length will result in 0 bits padding
     */
    memcpy(&tree->data[tree->data_position * tree->max_data_length], data, data_length);
    // move to next free position
    tree->data_position++;
    HIP_DEBUG("added data block\n");

    // close the tree, if it is full
    if (tree->data_position == tree->num_data_blocks) {
        HIP_DEBUG("tree is full! closing...\n");

        // fill up unused leaf nodes
        if (tree->num_data_blocks < tree->leaf_set_size) {
            HIP_IFEL(htree_add_random_data(tree, tree->leaf_set_size - tree->num_data_blocks),
                     1,
                     "failed to fill unused leaf nodes\n");
        }

        tree->is_open       = 0;
        tree->data_position = 0;
    }

out_err:
    return err;
}

/** adds random data item to the tree.
 *
 * @param       tree pointer to the tree
 * @param       num_random_blocks number of random blocks to be added
 * @return      always 0
 */
int htree_add_random_data(struct hash_tree *tree, const int num_random_blocks)
{
    HIP_ASSERT(tree != NULL);
    HIP_ASSERT(num_random_blocks > 0);
    HIP_ASSERT(tree->is_open > 0);
    HIP_ASSERT(tree->data_position + num_random_blocks <= tree->leaf_set_size);

    // add num_random_blocks random data to the data-array
    RAND_bytes(&tree->data[tree->data_position * tree->max_data_length],
               num_random_blocks * tree->max_data_length);
    // move to next free position
    tree->data_position += num_random_blocks;
    HIP_DEBUG("added %i random data block(s)\n", num_random_blocks);

    // close the tree, if it is full
    if (tree->data_position >= tree->num_data_blocks) {
        HIP_DEBUG("tree is full! closing...\n");

        // fill up unused leaf nodes
        if (tree->num_data_blocks < tree->leaf_set_size) {
            RAND_bytes(&tree->data[tree->data_position * tree->max_data_length],
                       (tree->leaf_set_size - tree->data_position) * tree->max_data_length);

            HIP_DEBUG("added %i leaf slots as padding\n",
                      tree->leaf_set_size - tree->data_position);
        }

        tree->is_open       = 0;
        tree->data_position = 0;
    }

    return 0;
}

/** adds random secrets to the tree.
 *
 * @param       tree pointer to the tree
 * @return      always 0
 */
int htree_add_random_secrets(struct hash_tree *tree)
{
    int err = 0;

    HIP_ASSERT(tree != NULL);
    HIP_ASSERT(tree->secrets != NULL);
    HIP_ASSERT(tree->secret_length > 0);

    // add num_random_blocks random data to the data-array
    RAND_bytes(&tree->secrets[0],
               tree->num_data_blocks * tree->secret_length);

    HIP_DEBUG("random secrets added\n");

    return err;
}

/** generates the nodes for a tree with completely filled leaf set,
 * otherwise it fills up the remaining data items with random data
 *
 * @param       tree pointer to the tree
 * @param       leaf_gen leaf generator function pointer
 * @param       node_gen node generator function pointer
 * @param       gen_args arguments for the generators
 * @return      0 on success, -1 otherwise
 */
int htree_calc_nodes(struct hash_tree *tree,
                     const htree_leaf_gen leaf_gen,
                     const htree_node_gen node_gen,
                     const struct htree_gen_args *gen_args)
{
    int level_width = 0, i, err = 0;
    // first leaf to be used when calculating next tree level in bytes
    int            source_index = 0;
    int            target_index = 0;
    unsigned char *secret       = NULL;

    HIP_ASSERT(tree != NULL);
    HIP_ASSERT(tree->is_open == 0);
    HIP_ASSERT(tree->data_position == 0);

    /* traverse all data blocks and create the leafs */
    HIP_DEBUG("computing leaf nodes: %i\n", tree->leaf_set_size);

    for (i = 0; i < tree->leaf_set_size; i++) {
        // only use secrets if they are defined
        if (tree->secret_length > 0) {
            secret = &tree->secrets[i * tree->secret_length];
        }

        // input: i-th data block -> output as i-th node-array element
        HIP_IFEL(leaf_gen(&tree->data[i * tree->max_data_length], tree->max_data_length,
                          secret, tree->secret_length,
                          &tree->nodes[i * tree->node_length], gen_args),
                 -1, "failed to calculate leaf hashes\n");
    }

    /* compute hashes on all other levels */
    HIP_DEBUG("computing intermediate nodes and root...\n");

    // the leaf level has got full width
    level_width = tree->leaf_set_size;

    // based on the current level, we are calculating the nodes for the next level
    while (level_width > 1) {
        HIP_DEBUG("calculating nodes: %i\n", level_width / 2);

        /* set the target for the this level directly behind the
         * already calculated nodes of the previous level */
        target_index = source_index + (level_width * tree->node_length);

        /* we always handle two elements at once */
        for (i = 0; i < level_width; i += 2) {
            HIP_IFEL(node_gen(&tree->nodes[source_index + (i * tree->node_length)],
                              &tree->nodes[source_index + ((i + 1) * tree->node_length)],
                              tree->node_length,
                              &tree->nodes[target_index + ((i / 2) * tree->node_length)],
                              gen_args), -1,
                     "failed to calculate hashes of intermediate nodes\n");

            // this means we're calculating the root node
            if (level_width == 2) {
                tree->root = &tree->nodes[target_index + ((i / 2) * tree->node_length)];
            }
        }

        // next level has got half the elements
        level_width = level_width / 2;

        /* use target index of this level as new source field */
        source_index = target_index;
    }

out_err:
    return err;
}

/** gets the number of remaining elements in the tee
 *
 * @param       tree given tree
 * @return number of remaining elements
 */
int htree_get_num_remaining(const struct hash_tree *tree)
{
    return tree->num_data_blocks - tree->data_position;
}

/** checks if the hash tree contains further unrevealed data items
 *
 * @param       tree pointer to the tree
 * @return      1 if more elements, else 0
 */
int htree_has_more_data(const struct hash_tree *tree)
{
    return tree->data_position < tree->num_data_blocks;
}

/** gets the offset of the next unrevealed data item
 *
 * @param       tree pointer to the tree
 * @return      offset of the data item
 *
 * NOTE: this increases the internal pointer to the current element
 */
int htree_get_next_data_offset(struct hash_tree *tree)
{
    int data_offset = 0;

    data_offset = tree->data_position;

    tree->data_position++;

    return data_offset;
}

/** gets the elements of the verification branch from a computed tree
 *
 * @param       tree pointer to the hash tree
 * @param       data_index leaf position for which the verification branch is fetched
 * @param       nodes buffer with sufficient space for branch nodes, if NULL buffer will be malloced here
 * @param       branch_length destination buffer length, returns used space
 * @return      buffer containing the branch nodes, NULL on error
 */
unsigned char *htree_get_branch(const struct hash_tree *tree,
                                const int data_index,
                                unsigned char *nodes,
                                int *branch_length)
{
    int            tree_level     = 0;
    int            level_width    = 0;
    int            source_index   = 0;
    int            sibling_offset = 0;
    int            tmp_index      = 0;
    int            err            = 0;
    unsigned char *branch_nodes   = NULL;

    HIP_ASSERT(tree != NULL);
    HIP_ASSERT(data_index >= 0 && data_index < tree->num_data_blocks);

    // use local (unconst) variable for tree traversal
    tmp_index = data_index;

    // branch includes all elements excluding the root
    *branch_length = tree->depth * tree->node_length;

    HIP_DEBUG("tree->depth: %i\n", tree->depth);

    // use provided buffer, if available; else alloc
    if (!nodes) {
        branch_nodes = malloc(*branch_length);
    } else {
        branch_nodes = nodes;
    }

    // traverse bottom up
    level_width = tree->leaf_set_size;

    // don't include root
    while (level_width > 1) {
        HIP_DEBUG("level_width: %i\n", level_width);

        // for an uneven data_index the previous node is the sibling, else the next
        sibling_offset = tmp_index & 1 ? -1 : 1;

        // copy branch-node from node-array to buffer
        memcpy(&branch_nodes[tree_level * tree->node_length],
               &tree->nodes[source_index +
                            ((tmp_index + sibling_offset) * tree->node_length)],
               tree->node_length);

        // proceed by one level
        source_index += level_width * tree->node_length;
        level_width   = level_width >> 1;
        tmp_index     = tmp_index >> 1;
        tree_level++;
    }

    if (err) {
        free(branch_nodes);
        branch_nodes = NULL;
    }

    return branch_nodes;
}

/** gets the data item at the specified position
 *
 * @param       tree pointer to the hash tree
 * @param       data_index leaf position for which the data item is returned
 * @param       data_length length of the returned data item
 * @return      pointer to the data item, NULL in case of an error
 */
const unsigned char *htree_get_data(const struct hash_tree *tree,
                                    const int data_index,
                                    int *data_length)
{
    HIP_ASSERT(tree != NULL);
    HIP_ASSERT(data_index >= 0 && data_index < tree->num_data_blocks);
    HIP_ASSERT(data_length != NULL);

    *data_length = tree->max_data_length;

    return &tree->data[data_index * tree->max_data_length];
}

/** gets the secret at the specified position
 *
 * @param       tree pointer to the hash tree
 * @param       secret_index leaf position for which the secret is returned
 * @param       secret_length length of the returned secret
 * @return      pointer to the secret, NULL in case of an error
 */
const unsigned char *htree_get_secret(const struct hash_tree *tree,
                                      const int secret_index,
                                      int *secret_length)
{
    HIP_ASSERT(tree != NULL);
    HIP_ASSERT(secret_index >= 0 && secret_index < tree->num_data_blocks);
    HIP_ASSERT(secret_length != NULL);

    *secret_length = tree->secret_length;

    if (tree->secret_length > 0) {
        return &tree->secrets[secret_index * tree->secret_length];
    } else {
        return NULL;
    }
}

/** gets the root node of the hash tree
 *
 * @param       tree pointer to the hash tree
 * @param       root_length length of the returned root element
 * @return      pointer to the root element, NULL in case of an error
 */
const unsigned char *htree_get_root(const struct hash_tree *tree,
                                    int *root_length)
{
    HIP_ASSERT(tree != NULL);

    if (tree->root) {
        *root_length = tree->node_length;
    } else {
        *root_length = 0;
    }

    return tree->root;
}

/** checks the data item and an verification branch against the root
 *
 * @param       root pointer to the root
 * @param       root_length length of the root node
 * @param       branch_nodes buffer containing the branch nodes
 * @param       branch_length length of the verification branch
 * @param       verify_data the data item to be verified
 * @param       data_length length of the data item
 * @param       data_index index of the data item in the leaf set
 * @param       secret potentially incorporated secret
 * @param       secret_length length of the secret
 * @param       leaf_gen leaf generator function pointer
 * @param       node_gen node generator function pointer
 * @param       gen_args arguments for the generators
 * @return      0 if successful, 1 if invalid, -1 in case of an error
 */
int htree_verify_branch(const unsigned char *root,
                        const int root_length,
                        const unsigned char *branch_nodes,
                        const uint32_t branch_length,
                        const unsigned char *verify_data,
                        const int data_length,
                        const uint32_t data_index,
                        const unsigned char *secret,
                        const int secret_length,
                        const htree_leaf_gen leaf_gen,
                        const htree_node_gen node_gen,
                        const struct htree_gen_args *gen_args)
{
    /* space for two nodes to be hashed together */
    unsigned char buffer[2 * root_length];
    int           num_nodes      = 0;
    int           sibling_offset = 0;
    int           tmp_index      = 0;
    int           err            = 0, i;

    HIP_ASSERT(root != NULL);
    HIP_ASSERT(root_length > 0);
    HIP_ASSERT(branch_nodes != NULL);
    HIP_ASSERT(branch_length > 0);
    HIP_ASSERT(verify_data != NULL);
    HIP_ASSERT(data_length > 0);

    if (secret_length > 0) {
        HIP_ASSERT(secret != NULL);
    }

    // use local (unconst) variable for tree traversal
    tmp_index = data_index;

    num_nodes = branch_length / root_length;

    // +1 as we have to calculate the leaf too
    for (i = 0; i < num_nodes + 1; i++) {
        HIP_DEBUG("round %i\n", i);

        // determines where to put the sibling in the buffer
        sibling_offset = tmp_index & 1 ? 0 : 1;

        /* in first round we have to calculate the leaf */
        if (i > 0) {
            /* hash previous buffer and overwrite partially */
            HIP_IFEL(node_gen(&buffer[0], &buffer[root_length], root_length,
                              &buffer[(1 - sibling_offset) * root_length], gen_args),
                     -1, "failed to calculate node hash\n");
        } else {
            /* hash data in order to derive the hash tree leaf */
            HIP_IFEL(leaf_gen(verify_data, data_length, secret, secret_length,
                              &buffer[(1 - sibling_offset) * root_length], gen_args), -1,
                     "failed to calculate leaf hash\n");
        }

        if (i < num_nodes) {
            // copy i-th branch node to the free slot in the buffer
            memcpy(&buffer[sibling_offset * root_length], &branch_nodes[i * root_length],
                   root_length);

            // proceed to next level
            tmp_index = tmp_index / 2;
        }

        HIP_HEXDUMP("buffer slot 1: ", &buffer[0], root_length);
        HIP_HEXDUMP("buffer slot 2: ", &buffer[root_length], root_length);
    }

    HIP_HEXDUMP("calculated root: ", &buffer[(1 - sibling_offset) * root_length],
                root_length);
    HIP_HEXDUMP("stored root: ", root, root_length);

    // check if the calculated root matches the stored one
    if (!memcmp(&buffer[(1 - sibling_offset) * root_length], root, root_length)) {
        HIP_DEBUG("branch successfully verified\n");
    } else {
        HIP_DEBUG("branch invalid\n");

        err = 1;
    }

out_err:
    return err;
}

/** generates a leaf node from a given data item
 *
 * @param       data data item to be hashed
 * @param       data_length length of the data item
 * @param       secret potentially incorporated secret
 * @param       secret_length length of the secret
 * @param       dst_buffer buffer for the generated leaf node
 * @param       gen_args arguments for the generator
 * @return      always 0
 */
int htree_leaf_generator(const unsigned char *data,
                         const int data_length,
                         const unsigned char *secret,
                         const int secret_length,
                         unsigned char *dst_buffer,
                         UNUSED const struct htree_gen_args *gen_args)
{
    int                  err = 0;
    unsigned char        buffer[data_length + secret_length];
    const unsigned char *hash_data        = NULL;
    int                  hash_data_length = 0;

    if (secret && secret_length > 0) {
        memcpy(&buffer[0], data, data_length);
        memcpy(&buffer[data_length], secret, secret_length);

        hash_data        = buffer;
        hash_data_length = data_length + secret_length;
    } else {
        hash_data        = data;
        hash_data_length = data_length;
    }

    HIP_IFEL(!SHA1(hash_data, hash_data_length, dst_buffer), -1,
             "failed to calculate hash\n");

out_err:
    return err;
}

/** generates an intermediate node from two hash tree nodes
 *
 * @param       left_node the left node to be hashed
 * @param       right_node the right node to be hashed
 * @param       node_length length of each node
 * @param       dst_buffer buffer for the generated intermediate node
 * @param       gen_args arguments for the generator
 * @return      0 on success, -1 in case of an error
 *
 * NOTE: the calling function has to ensure that left and right node are in
 *       subsequent memory blocks
 */
int htree_node_generator(const unsigned char *left_node,
                         UNUSED const unsigned char *right_node,
                         const int node_length,
                         unsigned char *dst_buffer,
                         UNUSED const struct htree_gen_args *gen_args)
{
    int err = 0;

    /* the calling function has to ensure that left and right node are in
     * subsequent memory blocks */
    HIP_IFEL(!SHA1(left_node, 2 * node_length, dst_buffer), -1,
             "failed to calculate hash\n");

out_err:
    return err;
}
