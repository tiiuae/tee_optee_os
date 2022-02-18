/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 */

/*
 * Interface with tee-supplicant for file operations
 */

#ifndef TEE_FS_RPC_H
#define TEE_FS_RPC_H

#include <stdbool.h>
#include <stddef.h>
#include <tee_api_types.h>
#include <tee/tee_fs.h>

struct thread_param_memref {
	size_t offs;
	size_t size;
	struct mobj *mobj;
};

struct thread_param_value {
	uint64_t a;
	uint64_t b;
	uint64_t c;
};

/*
 * Note that there's some arithmetics done on the value so it's important
 * to keep in IN, OUT, INOUT order.
 */
enum thread_param_attr {
	THREAD_PARAM_ATTR_NONE = 0,
	THREAD_PARAM_ATTR_VALUE_IN,
	THREAD_PARAM_ATTR_VALUE_OUT,
	THREAD_PARAM_ATTR_VALUE_INOUT,
	THREAD_PARAM_ATTR_MEMREF_IN,
	THREAD_PARAM_ATTR_MEMREF_OUT,
	THREAD_PARAM_ATTR_MEMREF_INOUT,
};

struct thread_param {
	enum thread_param_attr attr;
	union {
		struct thread_param_memref memref;
		struct thread_param_value value;
	} u;
};

#define THREAD_PARAM_MEMREF(_direction, _mobj, _offs, _size) \
	(struct thread_param){ \
		.attr = THREAD_PARAM_ATTR_MEMREF_ ## _direction, .u.memref = { \
		.mobj = (_mobj), .offs = (_offs), .size = (_size) } \
	}

#define THREAD_PARAM_VALUE(_direction, _a, _b, _c) \
	(struct thread_param){ \
		.attr = THREAD_PARAM_ATTR_VALUE_ ## _direction, .u.value = { \
		.a = (_a), .b = (_b), .c = (_c) } \
	}

struct tee_fs_rpc_operation {
	uint32_t id;
	struct thread_param params[THREAD_RPC_MAX_NUM_PARAMS];
	size_t num_params;
};

struct tee_fs_dirfile_fileh;

TEE_Result tee_fs_rpc_open_dfh(uint32_t id,
			       const struct tee_fs_dirfile_fileh *dfh, int *fd);
TEE_Result tee_fs_rpc_create_dfh(uint32_t id,
				 const struct tee_fs_dirfile_fileh *dfh,
				 int *fd);
TEE_Result tee_fs_rpc_close(uint32_t id, int fd);

TEE_Result tee_fs_rpc_read_init(struct tee_fs_rpc_operation *op,
				uint32_t id, int fd, tee_fs_off_t offset,
				size_t data_len, void **out_data);
TEE_Result tee_fs_rpc_read_final(struct tee_fs_rpc_operation *op,
				 size_t *data_len);

TEE_Result tee_fs_rpc_write_init(struct tee_fs_rpc_operation *op,
				 uint32_t id, int fd, tee_fs_off_t offset,
				 size_t data_len, void **data);
TEE_Result tee_fs_rpc_write_final(struct tee_fs_rpc_operation *op);


TEE_Result tee_fs_rpc_truncate(uint32_t id, int fd, size_t len);
TEE_Result tee_fs_rpc_remove_dfh(uint32_t id,
				 const struct tee_fs_dirfile_fileh *dfh);
#endif /* TEE_FS_RPC_H */
