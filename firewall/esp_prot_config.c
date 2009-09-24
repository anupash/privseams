/*
 * esp_prot_conf.c
 *
 *  Created on: 21.09.2009
 *      Author: Rene Hummen
 */

#include "esp_prot_config.h"

const char *config_file = {"firewall/esp_prot_conf.cfg"};

const char *path_token_transform = {"token_config.token_transform"};

const char *path_num_parallel_hchains = {"token_config.token_modes.num_parallel_hchains"};

const char *path_ring_buffer_size = {"token_config.token_modes.ring_buffer_size"};
const char *path_num_linear_elements = {"token_config.token_modes.num_linear_elements"};
const char *path_num_random_elements = {"token_config.token_modes.num_random_elements"};

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
	extern long token_transform;
	extern long num_parallel_hchains;
	extern long ring_buffer_size;
	extern long num_linear_elements;
	extern long num_random_elements;
	extern long hash_length;
	extern long hash_structure_length;
	int err = 0;

	// process parallel hchains-related settings
	if (!config_lookup_int(cfg, path_token_transform, &token_transform))
	{
		token_transform = 0;
	}
	HIP_DEBUG("token_transform: %i\n", token_transform);

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


	switch (token_transform)
	{
		case ESP_PROT_TFM_PLAIN:
			num_parallel_hchains = 1;
			ring_buffer_size = 0;
			num_linear_elements = 0;
			num_random_elements = 0;
			break;
		case ESP_PROT_TFM_PARALLEL:
			if (!config_lookup_int(cfg, path_num_parallel_hchains, &num_parallel_hchains))
			{
				num_parallel_hchains = 2;
			}

			ring_buffer_size = 0;
			num_linear_elements = 0;
			num_random_elements = 0;

			break;
		case ESP_PROT_TFM_CUMULATIVE:
			num_parallel_hchains = 1;

			if (!config_lookup_int(cfg, path_ring_buffer_size, &ring_buffer_size))
			{
				ring_buffer_size = 64;
			}

			if (!config_lookup_int(cfg, path_num_linear_elements, &num_linear_elements))
			{
				num_linear_elements = 1;
			}

			if (!config_lookup_int(cfg, path_num_random_elements, &num_random_elements))
			{
				num_random_elements = 0;
			}

			break;
		case ESP_PROT_TFM_PARA_CUMUL:
			if (!config_lookup_int(cfg, path_num_parallel_hchains, &num_parallel_hchains))
			{
				num_parallel_hchains = 1;
			}

			if (!config_lookup_int(cfg, path_ring_buffer_size, &ring_buffer_size))
			{
				ring_buffer_size = 64;
			}

			if (!config_lookup_int(cfg, path_num_linear_elements, &num_linear_elements))
			{
				num_linear_elements = 1;
			}

			if (!config_lookup_int(cfg, path_num_random_elements, &num_random_elements))
			{
				num_random_elements = 0;
			}

			break;
		case ESP_PROT_TFM_TREE:
			num_parallel_hchains = 1;
			ring_buffer_size = 0;
			num_linear_elements = 0;
			num_random_elements = 0;
			break;
		default:
			HIP_ERROR("unknown token transform!\n");

			err = -1;
			goto out_err;
			break;
	}

	HIP_DEBUG("num_parallel_hchains: %i\n", num_parallel_hchains);
	HIP_DEBUG("ring_buffer_size: %i\n", ring_buffer_size);
	HIP_DEBUG("num_linear_elements: %i\n", num_linear_elements);
	HIP_DEBUG("num_random_elements: %i\n", num_random_elements);


	// do some sanity checks here
	HIP_IFEL(hash_length <= 0, -1, "hash length has insufficient length\n");
	HIP_IFEL(hash_structure_length <= 0, -1, "hash structure length has insufficient length\n");

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

	// do some sanity checks here
	HIP_IFEL(num_hchains_per_item <= 0, -1, "num hchains per item has insufficient length\n");
	HIP_IFEL(num_hierarchies <= 0, -1, "num_hierarchies has insufficient length\n");
	HIP_IFEL(refill_threshold < 0.0 || refill_threshold > 1.0, -1, "refill_threshold not within boundaries\n");
	HIP_IFEL(update_threshold < 0.0 || update_threshold > 1.0, -1, "update_threshold not within boundaries\n");

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

	// do some sanity checks here
	HIP_IFEL(window_size <= 0, -1, "window size has insufficient length\n");

  out_err:
	return err;
}
