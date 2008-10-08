/*
 *  hashtree.c
 *
 *  Created by Tobias Heer on 21.04.08.
 *  Copyright 2008 Tobias Heer. All rights reserved.
 *
 */

#include "hashtree.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>

#include <openssl/sha.h>
#include <openssl/rand.h>


/*!
 * \brief Create empty MT tree.
 *
 *  Create empty MT tree. This is the first step when SIGNING data.
 *
 * \author  Tobias Heer
 *
 * \param treeSize Size of the tree (number of leaf elements)
 * \param buffer Size of each data packet (leaf node)
 * \param nodeSize Size of the MT nodes (size of hash function).
 *
 * \return A pointer to the tree, NULL in case of an error.
 *
 * \note The memory must be freed elsewhere.
 */
hash_tree_t* htree_init(int num_data_blocks, int max_data_length, int node_length)
{
    hash_tree_t *tree = NULL;
    int err = 0;

    // TODO we should check here that it's a power of 2
    HIP_ASSERT(num_data_blocks > 0);
    HIP_ASSERT(max_data_length > 0);
    HIP_ASSERT(node_length > 0);

    // allocate the memory for the tree
    HIP_IFEL(!(tree = malloc(sizeof(hash_tree_t))), -1, "failed to allocate memory\n");
    HIP_IFEL(!(tree->data = (char*) malloc(num_data_blocks * max_data_length)), -1,
    		"failed to allocate memory\n");
    // a binary tree with n leafs has got 2n-1 total nodes
    HIP_IFEL(!(tree->nodes = (char*) malloc(node_length * num_data_blocks * 2)), -1,
    		"failed to allocate memory\n");

    // init ht elements to 0
    bzero(tree, sizeof(hash_tree_t));
    bzero(tree->leafs, num_data_blocks * max_data_length);
    bzero(tree->nodes, node_length * num_data_blocks * 2);

    tree->is_open = 1;
    tree->data_position = 0;
    tree->num_data_blocks = num_data_blocks;
    tree->max_data_length = max_data_length;
    tree->node_length = node_length;
    tree->depth = ceil(log2(num_data_blocks));

  out_err:
	if (err)
	{
		if (tree->nodes)
			free(tree->nodes);
		if (tree->data)
			free(tree->data);
		if (tree)
			free(tree);

		tree = NULL;
	}

    return tree;
}

/*!
 * \brief Add a leaf to a tree.
 *
 *  Attach a leaf to an open tree.
 *
 * \author  Tobias Heer
 *
 * \param tree Pointer to the tree
 * \param data Payload data buffer
 * \param len  Length of the data buffer
 *
 * \return 0.
 */
int htree_add_data(hash_tree_t *tree, char *data, size_t data_length)
{
	HIP_ASSERT(tree != NULL);
	HIP_ASSERT(data != NULL);
	HIP_ASSERT(data_length > 0 && data_length <= tree->max_data_length);
    HIP_ASSERT(tree->is_open > 0);
    HIP_ASSERT(tree->data_position < tree->num_data_blocks);

    // add the leaf the leaf-array
    // TODO check offset
    memcpy(&tree->data[tree->data_position * tree->max_data_length], data, data_length);
    // move to next free position
    tree->data_position++;
    HIP_DEBUG("added data block\n");

    // close the tree, if it is full
    if(tree->data_position == tree->num_data_blocks)
    {
        HIP_DEBUG("tree is full! closing...\n");
        tree->is_open = 0;
        tree->data_position = 0;
    }

    return 0;
}

int htree_add_random_data(hash_tree_t *tree, int num_random_blocks)
{
	HIP_ASSERT(tree != NULL);
	HIP_ASSERT(num_random_blocks > 0);
    HIP_ASSERT(tree->is_open > 0);
    HIP_ASSERT(tree->data_position + num_random_blocks <= tree->num_data_blocks);

    // add num_random_blocks random data to the data-array
    // TODO check offset
    RAND_bytes(&tree->data[tree->data_position],
    		num_random_blocks * tree->max_data_length);
    // move to next free position
    tree->data_position += num_random_blocks;
    HIP_DEBUG("added random data block\n");

    // close the tree, if it is full
    if(tree->data_position == tree->num_data_blocks)
    {
        HIP_DEBUG("tree is full! closing...\n");
        tree->is_open = 0;
        tree->leaf_position = 0;
    }

    return 0;
}

/*!
 * \brief Generate the nodes for a tree with filled leaves.
 *
 *  Generate the nodes for a tree with filled leaves. This closes the tree. No further leaves can be added.
 *
 * \author  Tobias Heer
 *
 * \param generateLeaf 		Leaf generator function pointer
 * \param generateNode		Node generator function pointer
 * \param generatorArgs 	Arguments for the generators
 * \return 0
 */
int htree_compute_nodes(hash_tree_t *tree, htree_leaf_gen_t leaf_gen,
		htree_node_gen_t node_gen)
{
	int level_width = 0, i, err = 0;
	// first leaf to be used when calculating next tree level in bytes
    int source_index = 0;
    int target_index = 0;

	HIP_ASSERT(tree != NULL);
	// tree has to be full
	HIP_ASSERT(tree->is_open == 0);
	HIP_ASSERT(tree->data_position == 0);

    /* traverse all data blocks and create the leafs */
    HIP_DEBUG("computing leaf nodes (%d)\n", tree->num_data_blocks);

    for(i = 0; i < tree->num_data_blocks; i++)
    {
    	HIP_DEBUG("calling leaf generator function...\n");

    	// input: i-th data block -> output as i-th node-array element
    	HIP_IFEL(leaf_gen(&tree->data[i * tree->max_data_length], tree->max_data_length,
    			&tree->nodes[i * tree->node_length], NULL), -1,
    			"failed to calculate leaf hashes\n");
    }

    /* compute hashes on all other levels except the root */
    HIP_DEBUG("computing intermediate nodes...\n");

    // the leaf level has got full width
    level_width = tree->num_data_blocks;

    while(level_width > 1)
    {
        /* set the target for the this level directly behind the
         * already calculated nodes of the previous level */
        target_index = source_index + (level_width * tree->node_length);

        /* we always handle two elements at once */
        for(i = 0; i < level_width; i += 2)
        {
        	HIP_DEBUG("calling node generator function...\n");

        	HIP_IFEL(node_gen(&tree->nodes[source_index + (i * tree->node_length)],
        			&tree->nodes[source_index + ((i + 1) * tree->node_length)],
        			&tree->nodes[target_index + ((i / 2) * tree->node_length)],
        			tree->node_length, NULL), -1,
        			"failed to calculate hashes of intermediate nodes\n");
        }

        // next level has got half the elements
        level_width = level_width >> 1;
        HIP_DEBUG("next level_width: %d\n", level_width);

        /* use target index of this level as new source field */
        source_index = target_index;
    }

  out_err:
    return err;
}

/*!
 * \brief Check the data and an uptree against the root.
 *
 *   Check the data and an uptree against the root.
 *
 * \author  Tobias Heer
 *
 * \param tree 		Pointer to the root
 * \param leafIndex	Leaf position for which the uptree was fetched
 * \param data		Data buffer
 * \param dataLen	Data buffer length
 * \param nodes		Uptree buffer
 * \param nodeLen	Uptree buffer length
 *
 * \return 0
 */
int ht_verifyBuffer(ht_root_t* root,
                    int nodeIndex,
                    char* data,
                    int dataLen,
                    char* nodes,
                    int nodeLen){

    /* Check that buffer length matches tree depth*/
    if(root->treeDepth * root->nodeSize != nodeLen){
        printf("ht_getUpTree: Buffer space mismatch (%d != %d)\n",
               nodeLen,
               root->treeDepth * root->nodeSize);
        exit(1);
    }
    if(nodeLen == 0){
        printf("Node buffer length is 0\n");
        exit(1);
    }
    char* nodeBuffer;
    nodeBuffer = malloc(sizeof(char) * root->nodeSize * 2); /* space for two nodes to be hashed together */
    int modifier;
    int i;
	for(i = 0; i < root-> treeDepth+1; i++){
        printf("Round %d\n", i);
        modifier = nodeIndex & 1?1:0;

        /* For the first round use the hashed packet */

        if(i != 0 ){
            /* Hash previous buffer */

            SHA( (unsigned char*) nodeBuffer, root->nodeSize * 2,  (unsigned char*) nodeBuffer + modifier*root->nodeSize);

        }else{
            /* Hash input data */
            SHA( (unsigned char*) data, dataLen,  (unsigned char*) nodeBuffer + modifier*root->nodeSize);
        }


        memcpy(nodeBuffer+(1-modifier)*root->nodeSize, nodes+root->nodeSize * i, root->nodeSize);
        printf("Buffer1: ");
        hexdump(nodeBuffer, root->nodeSize);
        printf("\nBuffer2: ");
        hexdump(nodeBuffer + root->nodeSize, root->nodeSize);
        printf("\n");
    }
    if(memcmp(nodeBuffer + modifier*root->nodeSize, root->node, root->nodeSize) != 0){
        printf("Signature invalid\n");
        printf("Comp: ");
        hexdump(nodeBuffer + modifier*root->nodeSize, root->nodeSize);
        printf("\nRoot: ");
        hexdump(root->node, root->nodeSize);
        printf("\n");
        return -1;
    }
}

int htree_leaf_generator(unsigned char *data, int data_length,
		unsigned char *dst_buffer, htree_gen_args_t *gen_args)
{
	int err = 0;

	HIP_IFEL(!SHA1(data, data_length, dst_buffer), -1, "failed to calculate hash\n");

  out_err:
	return err;
}

int htree_node_generator(unsigned char *left_node, unsigned char *right_node,
		   unsigned char *dst_buffer, int node_length, htree_gen_args_t *gen_args)
{
	int err = 0;
	unsigned char siblings[2 * node_length];

	memcpy(&siblings[0], left_node, node_length);
	memcpy(&siblings[node_length], right_node, node_length);

	HIP_IFEL(!SHA1(&siblings[0], 2 * node_length, dst_buffer), -1,
			"failed to calculate hash\n");

  out_err:
	return err;
}

/*!
 * \brief Create a root element for the tree and the corresponding tree.
 *
 * Create a root element for the tree. This is the first step when VERIFYING data.
 *
 * \author  Tobias Heer
 *
 * \param buffer Root data of the tree.
 * \param nodeSize Size of the MT nodes (size of hash function).
 * \param treeSize Size of the tree (number of leaf elements)
 *
 * \return A pointer to the root.
 *
 * \note The memory must be freed elsewhere.
 */
ht_root_t* ht_createRoot(char* buffer, size_t nodeSize, size_t treeSize)
{
    ht_root_t* root;

    if(treeSize == 0){
        printf("Root can not belong to 0 tree");
        exit(1);
    }

    root =  malloc(sizeof(hash_tree_t));
    bzero(root, sizeof(hash_tree_t));


    root->node = (char*) malloc(nodeSize);
    bzero(root->node, nodeSize);

    memcpy(root->node, (const void*) buffer, nodeSize);

    root->treeSize  = treeSize;
    root->treeDepth = ceil(log2(treeSize));
    root->nodeSize  = nodeSize;

    return root;
}

/*!
 * \brief Get the root element from a computed tree.
 *
 *  Get the root element from a computed tree.
 *
 * \author  Tobias Heer
 *
 * \param tree 		Pointer to the MT
 * \param buffer	Destination buffer
 * \param len		Destination buffer length
 * \return 0
 */
int ht_getRoot(hash_tree_t* tree, char* buffer, int len)
{
    if(len != tree->nodeSize){
        printf("getRoot: insufficient buffer space (%d != %d)",
               len,
               tree->nodeSize);
        exit(1);
    }
    memcpy(buffer, tree->node + 2 * (tree->size-1) * tree->nodeSize, tree->nodeSize);
    return 0;
}

/*!
 * \brief Get the uptree nodes from a computed tree.
 *
 *  Get the uptree nodes from a computed tree.
 *
 * \author  Tobias Heer
 *
 * \param tree 		Pointer to the MT
 * \param leafIndex	Leaf position for which the uptree is fetched
 * \param buffer	Destination buffer
 * \param len		Destination buffer length
 * \return 0
 */
int ht_getUpTree(hash_tree_t* tree, int leafIndex, char* buffer, size_t len){
    printf("super\n");
    // Check if buffer is sufficient (size of nodes * tree depth)
    if(len != tree->depth * tree->nodeSize){
        printf("ht_getUpTree: Buffer space mismatch (%d != %d)",
               len,
               tree->depth * tree->nodeSize);
    }

    // Start from bottom to root
    int j = 0;
    size_t levelSize  = tree->size;
    char* sourceBase = tree->node;
    int modifier     = 0;
    while (levelSize > 0) {
        modifier = leafIndex & 1?-1:1;
        // Fill buffer with node
        memcpy(buffer + j * tree->nodeSize,
               sourceBase + (leafIndex + modifier)* tree->nodeSize,
               tree->nodeSize);

        printf("\nLevelSize: %d\n", levelSize);
        sourceBase += (levelSize * tree->nodeSize);
        levelSize = levelSize >> 1;
        leafIndex = leafIndex  >> 1;
        j++;
        hexdump(buffer, len);

    }

    return 0;
}

/*!
 * \brief Print all leaves of a tree.
 *
 *  Print all leaves of a tree.
 *
 * \author  Tobias Heer
 *
 * \param tree 		Pointer to the MT
 * \return 0
 */
void htree_print_data(hash_tree_t *tree)
{
    int i;

    HIP_ASSERT(tree != NULL);

    HIP_DEBUG("printing data blocks...\n");

    for(i = 0; i < tree->num_data_blocks; i++)
    {
        HIP_HEXDUMP("data block: ", &tree->data[i * tree->max_data_length],
        		tree->max_data_length);
    }
}

/*!
 * \brief Print all nodes of a tree.
 *
 *  Print all nodes of a tree.
 *
 * \author  Tobias Heer
 *
 * \param tree 		Pointer to the MT
 * \return 0
 */
void htree_print_nodes(hash_tree_t *tree)
{
    int level_width = 0;
    int target_index = 0;
    int source_index = 0;
    int i = 0, j;

    HIP_ASSERT(tree != NULL);

    level_width = tree->num_data_blocks;

    HIP_DEBUG("printing hash tree nodes...\n");

    while (level_width > 0)
    {
        i++;
        HIP_DEBUG("printing level %i:\n", i);

        target_index = source_index + (level_width * tree->node_length);

        for(i = 0; i < level_width; i++){
            HIP_HEXDUMP("node: ", &tree->nodes[source_index + (i * tree->node_length)],
            		tree->node_length);
        }

        source_index = target_index;
        level_width = level_width >> 1;
    }
}

#if 0
/*!
 * \brief Create empty acknowledgement MT tree.
 *
 *  Create empty MT tree. This is the first step when Acknowledging packets.
 *
 * \author  Tobias Heer
 *
 * \param treeSize Size of the tree (number of leaf elements)
 * \param secretSize Size of each secret (part of the leaf node)
 * \param nodeSize Size of the MT nodes (size of hash function).
 *
 *
 * \return A pointer to the tree.
 *
 * \note The memory must be freed elsewhere.
 */
hash_tree_t* ht_createAckTree(size_t treeSize, size_t secretSize, size_t nodeSize){
    hash_tree_t* tree;

    tree =  malloc(sizeof(hash_tree_t));

    tree->leaf = (char*) malloc(secretSize*treeSize);
    RAND_bytes(tree->leaf, secretSize*treeSize);

    tree->node = (char*) malloc(nodeSize*treeSize);
    // TODO: This can be removed after testing
    bzero(tree->node, nodeSize*treeSize);



    tree->isOpen    = FALSE;
    tree->pos       = 0;
    tree->size      = treeSize;
    tree->depth = ceil(log2(treeSize));
    tree->leafSize  = secretSize;
    tree->nodeSize  = nodeSize;


    return tree;
}
#endif

#if 0
ht_hash* ht_generateSecrets(size_t numSecrets, size_t nodeSize){

	hash* stash = malloc(numSecrets * nodeSize);

	//check if memory was allocated
	if(stash == NULL)
		return 0;

	// fill stash with secrets
	get_random_bytes(stash, numSecrets * nodeSize);
	return stash;
}
#endif

#if 0
/*!
 * \brief Generate a node from a ack leaf.
 *
 *  Generate a node from a signature leaf. Used in ack trees.
 *
 * \author  Tobias Heer
 *
 * \param leaf  			Pointer to the leaf
 * \param index 			Leaf number
 * \param destinationBuffer Pointer to the node buffer location
 * \param leafSize 			Size of the Leaf
 * \param args				Variable argument field for using function pointers
 * \return Error code (see code for details).
 */
ht_err ht_ackLeafGenerator(unsigned char* leaf,
						uint16_t index,
						unsigned char* destinationBuffer,
						size_t leafSize,
						void* generatorArgs){

	assert(leaf != NULL);
	assert(generatorArgs != NULL);
	char* tempBuffer = (char *) generatorArgs;
	assert(destinationBuffer != NULL);
	printf("Setting bit 1,2\n");
	uint16_t netIndex = htonl(index);
	// copy index to buffer
	printf("Setting bit 1,2\n");
	memcpy(tempBuffer, &netIndex, sizeof(netIndex));
	printf("Copy Buffer\n");
	// copy hash value to buffer
	memcpy(tempBuffer+2, leaf, leafSize);

    printf("Temp Buffer %d: ", index);
    hexdump(tempBuffer, leafSize+2);
    printf("\n");

	if(SHA1(tempBuffer, leafSize, destinationBuffer))
		return ht_STht_SUCCESS;
	return ht_STht_ERR_UNSPECIFIED;
}
#endif

#if 0
/*!
 * \brief Generate a node from a signature leaf.
 *
 *  Generate a node from a signature leaf. Used in signature trees.
 *
 * \author  Tobias Heer
 *
 * \param leaf  			Pointer to the leaf
 * \param index 			Leaf number
 * \param destinationBuffer Pointer to the node buffer location
 * \param leafSize 			Size of the Leaf
 * \param args				Variable argument field for using function pointers
 * \return Error code.
 */
ht_err ht_sigLeafGenerator(unsigned char* leaf,
						uint16_t index,
						unsigned char* destinationBuffer,
						size_t leafSize,
						void* args){

	if(SHA1(leaf, leafSize, destinationBuffer))
		return ht_STht_SUCCESS;
	return ht_STht_ERR_UNSPECIFIED;

}
#endif

#if 0
/*!
 * \brief Generate a node from a ack node.
 *
 *  Generate a node from a signature node. Used in signature trees.
 *
 * \author  Tobias Heer
 *
 * \param leftNode 			Pointer to the left node
 * \param rightNode 		Pointer to the right node
 * \param index 			Left node number
 * \param destinationBuffer Pointer to the node buffer location
 * \param nodeSize 			Size of the node
 * \param args				Variable argument field for using function pointers
 * \return Error code (see code for details).
 */
ht_err ht_sigNodeGenerator(unsigned char* leftNode,
						unsigned char* rightNode,
						uint16_t index,
						unsigned char* destinationBuffer,
						size_t nodeSize,
						void* args){
	/** @NOTE: We assume that the left and the right node
	 *  are contained in a sequential byte buffer that starts
	 *  with leftNode. Hence, we ignore rightNode completely
	 */
	if(SHA1(leftNode, nodeSize*2, destinationBuffer))
		return ht_STht_SUCCESS;
	return ht_STht_ERR_UNSPECIFIED;
}
#endif
