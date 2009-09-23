/*
 * esp_prot_conf.c
 *
 *  Created on: 21.09.2009
 *      Author: Rene Hummen
 */

#include "esp_prot_config.h"

const char *config_file = {"firewall/esp_prot_conf.cfg"};

const char *path_parallel_hchains = {"token_config.token_modes.parallel_hchains"};
const char *path_num_parallel_hchains = {"token_config.token_modes.num_parallel_hchains"};

const char *path_cumulative_authentication = {"token_config.token_modes.cumulative_authentication"};
const char *path_ring_buffer_size = {"token_config.token_modes.ring_buffer_size"};
const char *path_num_linear_elements = {"token_config.token_modes.num_linear_elements"};
const char *path_num_random_elements = {"token_config.token_modes.num_random_elements"};

const char *path_hash_tree_based_auth = {"token_config.token_modes.hash_tree_based_auth"};
const char *path_differential_hchains = {"token_config.token_modes.differential_hchains"};
const char *path_tree_authed_hchains = {"token_config.token_modes.tree_authed_hchains"};

const char *path_hash_length = {"token_config.hash_length"};
const char *path_hash_structure_length = {"token_config.hash_structure_length"};


const char *path_num_hchains_per_item = {"sender.hcstore.num_hchains_per_item"};
const char *path_num_hierarchies = {"sender.hcstore.num_hierarchies"};
const char *path_refill_threshold = {"sender.hcstore.refill_threshold"};
const char *path_update_threshold = {"sender.update_threshold"};

const char *path_window_size = {"verifier.window_size"};


config_t * esp_prot_read_config()
{
	config_t *cfg = NULL;
	int err = 0;

	HIP_IFEL(!(cfg = (config_t *)malloc(sizeof(config_t))), -1, "Unable to allocate memory!\n");

	// init context and read file
	config_init(cfg);
	HIP_DEBUG("reading config file: %s...\n", config_file);
	HIP_IFEL(!config_read_file(cfg, config_file), -1, "unable to read config file\n");

  out_err:
	if (err)
	{
		esp_prot_release_config(cfg);
		cfg = NULL;
	}

	return cfg;
}

int esp_prot_release_config(config_t *cfg)
{
	int err = 0;

	config_destroy(cfg);

	if (cfg)
		free(cfg);

	return err;
}

int esp_prot_token_config(config_t *cfg)
{
	extern long parallel_hchains;
	extern long num_parallel_hchains;
	extern long cumulative_authentication;
	extern long ring_buffer_size;
	extern long num_linear_elements;
	extern long num_random_elements;
	extern long hash_tree_based_auth;
	extern long differential_hchains;
	extern long tree_authed_hchains;
	extern long hash_length;
	extern long hash_structure_length;
	int err = 0;

	// process parallel hchains-related settings
	if (!config_lookup_int(cfg, path_parallel_hchains, &parallel_hchains))
	{
		parallel_hchains = 0;
	}
	HIP_DEBUG("parallel_hchains: %i\n", parallel_hchains);

	if (parallel_hchains)
	{
		if (!config_lookup_int(cfg, path_num_parallel_hchains, &num_parallel_hchains))
		{
			num_parallel_hchains = 1;
		}
	} else
	{
		num_parallel_hchains = 1;
	}
	HIP_DEBUG("num_parallel_hchains: %i\n", num_parallel_hchains);


	// process cumulative authentication-related settings
	if (!config_lookup_int(cfg, path_cumulative_authentication, &cumulative_authentication))
	{
		cumulative_authentication = 0;
	}
	HIP_DEBUG("cumulative_authentication: %i\n", cumulative_authentication);

	if (cumulative_authentication)
	{
		if (!config_lookup_int(cfg, path_ring_buffer_size, &ring_buffer_size))
		{
			ring_buffer_size = 0;
		}

		if (!config_lookup_int(cfg, path_num_linear_elements, &num_linear_elements))
		{
			num_linear_elements = 0;
		}

		if (!config_lookup_int(cfg, path_num_random_elements, &num_random_elements))
		{
			num_random_elements = 0;
		}
	} else
	{
		ring_buffer_size = 0;
		num_linear_elements = 0;
		num_random_elements = 0;
	}
	HIP_DEBUG("ring_buffer_size: %i\n", ring_buffer_size);
	HIP_DEBUG("num_linear_elements: %i\n", num_linear_elements);
	HIP_DEBUG("num_random_elements: %i\n", num_random_elements);


	// process hash tree-based setting
	if (!config_lookup_int(cfg, path_hash_tree_based_auth, &hash_tree_based_auth))
	{
		hash_tree_based_auth = 0;
	}
	HIP_DEBUG("hash_tree_based_auth: %i\n", hash_tree_based_auth);

	// process hash tree-based setting
	if (!config_lookup_int(cfg, path_differential_hchains, &differential_hchains))
	{
		differential_hchains = 0;
	}
	HIP_DEBUG("differential_hchains: %i\n", differential_hchains);

	// process hash tree-authed hchains setting
	if (!config_lookup_int(cfg, path_tree_authed_hchains, &tree_authed_hchains))
	{
		tree_authed_hchains = 0;
	}
	HIP_DEBUG("tree_authed_hchains: %i\n", tree_authed_hchains);


	// process hash tree-based setting
	if (!config_lookup_int(cfg, path_hash_length, &hash_length))
	{
		hash_length = 20;
	}
	HIP_DEBUG("hash_length: %i\n", hash_length);

	// process hash tree-based setting
	if (!config_lookup_int(cfg, path_hash_structure_length, &hash_structure_length))
	{
		hash_structure_length = 16;
	}
	HIP_DEBUG("hash_structure_length: %i\n", hash_structure_length);

  out_err:
	return err;
}

int esp_prot_sender_config(config_t *cfg)
{
	extern long num_hchains_per_item;
	extern long num_hierarchies;
	extern double refill_threshold;
	extern double update_threshold;
	int err = 0;

	// process hcstore-related settings
	if (!config_lookup_int(cfg, path_num_hchains_per_item, &num_hchains_per_item))
	{
		num_hchains_per_item = 8;
	}
	HIP_DEBUG("num_hchains_per_item: %i\n", num_hchains_per_item);

	if (!config_lookup_int(cfg, path_num_hierarchies, &num_hierarchies))
	{
		num_hierarchies = 1;
	}
	HIP_DEBUG("num_hierarchies: %i\n", num_hierarchies);

	if (!config_lookup_float(cfg, path_refill_threshold, &refill_threshold))
	{
		refill_threshold = 0.5;
	}
	HIP_DEBUG("refill_threshold: %f\n", refill_threshold);

	// process update-related settings
	if (!config_lookup_float(cfg, path_update_threshold, &update_threshold))
	{
		update_threshold = 0.5;
	}
	HIP_DEBUG("update_threshold: %f\n", update_threshold);

  out_err:
	return err;
}

int esp_prot_verifier_config(config_t *cfg)
{
	extern long window_size;
	int err = 0;

	// process verification-related setting
	if (!config_lookup_int(cfg, path_window_size, &window_size))
	{
		window_size = 64;
	}
	HIP_DEBUG("window_size: %i\n", window_size);

  out_err:
	return err;
}
