/*
 * Copyright 2022, Unikie
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>
#include <string.h>
#include <tee/tee_fs.h>
#include <tee/tee_pobj.h>

#include "lfs.h"
#include "bd/lfs_rambd.h"

/* Local log level */
#ifndef OPTEE_RAMDISK_TRACE_LEVEL
#define OPTEE_RAMDISK_TRACE_LEVEL TRACE_LEVEL
#endif

#undef TRACE_LEVEL
#define TRACE_LEVEL OPTEE_RAMDISK_TRACE_LEVEL
#include <trace.h>

#include <utils/util.h>
#include <utils/zf_log.h>
#include <utils/zf_log_if.h>
#include <kernel/tee_misc.h>

static lfs_t lfs_ramdisk = { 0 };
static lfs_t *fs_handle = &lfs_ramdisk;

static struct lfs_rambd_config rambd_cfg = { .erase_value = -1 };
static lfs_rambd_t rambd_ctx = { .cfg = &rambd_cfg };

static const struct lfs_config ramdisk_cfg = {
    .read  = lfs_rambd_read,
    .prog  = lfs_rambd_prog,
    .erase = lfs_rambd_erase,
    .sync  = lfs_rambd_sync,

    // block device configuration
    .read_size = 16,
    .prog_size = 16,
    .block_size = 256,
    .block_count = 800, /* => ramdisk size: 256B * 800 = 200kB */
    .cache_size = 16,
    .lookahead_size = 16,
    .block_cycles = -1,

    .context = &rambd_ctx,
};

static uint32_t lsfs_err_to_tee_res(int lfs_err)
{
    switch(lfs_err) {
    case LFS_ERR_OK:
        return TEE_SUCCESS;
    case LFS_ERR_INVAL:
        return TEE_ERROR_BAD_PARAMETERS;
    case LFS_ERR_NOMEM:
        return TEE_ERROR_OUT_OF_MEMORY;
    case LFS_ERR_CORRUPT:
        return TEE_ERROR_CORRUPT_OBJECT;
    case LFS_ERR_NOSPC:
        return TEE_ERROR_STORAGE_NO_SPACE;
    case LFS_ERR_NOENT:
        return TEE_ERROR_ITEM_NOT_FOUND;
    case LFS_ERR_EXIST:
        return TEE_ERROR_ACCESS_CONFLICT;
    default:
        return TEE_ERROR_ACCESS_DENIED;
    }
}

#define BH_BUFFER_LEN   224 /* TEE_RPMB_FS_FILENAME_LENGTH */
static uint8_t bh_buffer[BH_BUFFER_LEN] = { 0 };

static TEE_Result uuid_to_fname(struct tee_pobj *po, uint8_t *buf, uint32_t len)
{
    uint32_t hslen = TEE_B2HS_HSBUF_SIZE(po->obj_id_len);

    if (len < hslen) {
        EMSG("ERROR: len: %d, '%s'", hslen, (char *)po->obj_id);
        return TEE_ERROR_SHORT_BUFFER;
    }

    tee_b2hs(po->obj_id, buf, po->obj_id_len, hslen);

    return TEE_SUCCESS;
}

TEE_Result ramdisk_fs_open(struct tee_pobj *po, size_t *size,
               struct tee_file_handle **fh)
{
    int ret = -1;
    lfs_file_t *file_handle = calloc(1, sizeof(lfs_file_t));

    /* include only RW flags, fail if file does not exist */
    int lfs_flags = po->flags & 0x3;

    if (!po || !size || !fh) {
        EMSG("ERROR: arguments");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (!file_handle) {
        EMSG("ERROR: out of memory");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = uuid_to_fname(po, bh_buffer, BH_BUFFER_LEN);
    if (ret) {
        return lsfs_err_to_tee_res(ret);
    }

    ret = lfs_file_open(fs_handle, file_handle, (char *)bh_buffer, lfs_flags);
    if (ret) {
        EMSG("ERROR: %d: %p", ret, file_handle);
        return lsfs_err_to_tee_res(ret);
    }

    ret = lfs_file_size(fs_handle, file_handle);
    if (ret < 0) {
        EMSG("ERROR: %d: %p", ret, file_handle);
        lfs_file_close(fs_handle, file_handle);
        free(file_handle);
        return lsfs_err_to_tee_res(ret);
    }

    *size = ret;

    *fh = (struct tee_file_handle *)file_handle;

    IMSG("handle: %p, size: %ld", file_handle, *size);

    return 0;
}

TEE_Result ramdisk_fs_create(struct tee_pobj *po, bool overwrite,
                 const void *head, size_t head_size,
                 const void *attr, size_t attr_size,
                 const void *data, size_t data_size,
                 struct tee_file_handle **fh)
{
    int ret = -1;
    lfs_file_t *file_handle = calloc(1, sizeof(lfs_file_t));

    /* include only RW flags, create a file if it does not exist */
    int lfs_flags = (po->flags & 0x3) | LFS_O_CREAT;

    uint32_t pos = 0;

    if (!po || !fh) {
        EMSG("ERROR: arguments");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (!file_handle) {
        EMSG("ERROR: out of memory");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (overwrite) {
        IMSG("LFS_O_TRUNC");
        lfs_flags |= LFS_O_TRUNC;
    }

    ret = uuid_to_fname(po, bh_buffer, BH_BUFFER_LEN);
    if (ret) {
        goto out;
    }

    ret = lfs_file_open(fs_handle, file_handle, (char *)bh_buffer, lfs_flags);
    if (ret) {
        EMSG("ERROR: %d: %p", ret, file_handle);
        goto out;
    }

    if (head && head_size) {
        ret = lfs_file_write(fs_handle, file_handle, head, head_size);
        if (ret < 0) {
            EMSG("ERROR: %d: %p", ret, file_handle);
            goto out_file_cleanup;
        }

        pos += ret;
    }

    if (attr && attr_size) {
        ret = lfs_file_write(fs_handle, file_handle, attr, attr_size);
        if (ret < 0) {
            EMSG("ERROR: %d: %p", ret, file_handle);
            goto out_file_cleanup;
        }

        pos += ret;
    }

    if (data && data_size) {
        ret = lfs_file_write(fs_handle, file_handle, data, data_size);
        if (ret < 0) {
            EMSG("ERROR: %d: %p", ret, file_handle);
            goto out_file_cleanup;
        }

        pos += ret;
    }

    ret = TEE_SUCCESS;

    *fh = (struct tee_file_handle *)file_handle;

    IMSG("h: %p, p: %d", file_handle, pos);

    return 0;

out_file_cleanup:
    lfs_file_close(fs_handle, file_handle);
    free(file_handle);
out:
    return lsfs_err_to_tee_res(ret);
}

void ramdisk_fs_close(struct tee_file_handle **fh)
{
    lfs_file_t *file_handle = (lfs_file_t *) *fh;

    if (!file_handle)
        return;

    IMSG("%p", file_handle);

    lfs_file_close(fs_handle, file_handle);

    free(*fh);
    *fh = NULL;
}

TEE_Result ramdisk_fs_read(struct tee_file_handle *fh, size_t pos,
               void *buf, size_t *len)
{
    int ret = -1;
    lfs_file_t *file_handle = (lfs_file_t *)fh;

    if (!fh || !buf) {
        EMSG("ERROR: arguments");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = lfs_file_seek(fs_handle, file_handle, pos, LFS_SEEK_SET);
    if (ret < 0) {
        EMSG("ERROR: %d: %p", ret, file_handle);
        return lsfs_err_to_tee_res(ret);
    }

    ret = lfs_file_read(fs_handle, file_handle, buf, *len);
    if (ret < 0) {
        EMSG("ERROR: %d: %p", ret, file_handle);
        return lsfs_err_to_tee_res(ret);
    }

    IMSG("%p, p: %ld, b: %ld, r: %d", file_handle, pos, *len, ret);

    *len = ret;

    return 0;
}

TEE_Result ramdisk_fs_write(struct tee_file_handle *fh, size_t pos,
                const void *buf, size_t len)
{
    int ret = -1;
    lfs_file_t *file_handle = (lfs_file_t *)fh;

    if (!fh || !buf) {
        EMSG("ERROR: arguments");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = lfs_file_seek(fs_handle, file_handle, pos, LFS_SEEK_SET);
    if (ret < 0) {
        EMSG("ERROR: %d: %p", ret, file_handle);
        goto out;
    }

    ret = lfs_file_write(fs_handle, file_handle, buf, len);
    if (ret < 0) {
        EMSG("ERROR: %d: %p", ret, file_handle);
        goto out;
    }

    if (ret != len) {
        EMSG("write failed: %d / %ld", ret, len);
        ret = LFS_ERR_NOSPC;
        goto out;
    }

    IMSG("%p, p: %ld, l: %ld", file_handle, pos, len);

    ret = 0;

out:
    return lsfs_err_to_tee_res(ret);
}

TEE_Result ramdisk_fs_truncate(struct tee_file_handle *fh, size_t size)
{
    int ret = -1;
    lfs_file_t *file_handle = (lfs_file_t *) fh;

    if (!fh) {
        EMSG("ERROR: arguments");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    IMSG("%p, s: %ld", file_handle, size);

    ret = lfs_file_truncate(fs_handle, file_handle, size);
    if (ret) {
        EMSG("ERROR: %d", ret);
    }

    return lsfs_err_to_tee_res(ret);
}

TEE_Result ramdisk_fs_rename(struct tee_pobj *old_po, struct tee_pobj *new_po,
                 bool overwrite)
{
    ZF_LOGF("not implemented");
}

TEE_Result ramdisk_fs_remove(struct tee_pobj *po)
{
    int ret = -1;

    if (!po) {
        EMSG("ERROR: arguments");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = uuid_to_fname(po, bh_buffer, BH_BUFFER_LEN);
    if (ret) {
        return lsfs_err_to_tee_res(ret);
    }

    ret = lfs_remove(fs_handle, (char *)bh_buffer);
    if (ret) {
        EMSG("ERROR: %d", ret);
    }

    return lsfs_err_to_tee_res(ret);
}

TEE_Result ramdisk_fs_opendir(const TEE_UUID *uuid, struct tee_fs_dir **d)
{
    ZF_LOGF("not implemented");
}

void ramdisk_fs_closedir(struct tee_fs_dir *d)
{
    ZF_LOGF("not implemented");
}

TEE_Result ramdisk_fs_readdir(struct tee_fs_dir *d, struct tee_fs_dirent **ent)
{
    ZF_LOGF("not implemented");
}

const struct tee_file_operations ramdisk_fs_ops = {
    .open = ramdisk_fs_open,
    .create = ramdisk_fs_create,
    .close = ramdisk_fs_close,
    .read = ramdisk_fs_read,
    .write = ramdisk_fs_write,
    .truncate = ramdisk_fs_truncate,
    .rename = ramdisk_fs_rename,
    .remove = ramdisk_fs_remove,
    .opendir = ramdisk_fs_opendir,
    .closedir = ramdisk_fs_closedir,
    .readdir = ramdisk_fs_readdir,
};

TEE_Result ramdisk_fs_init(void **buf_out,
                           uint32_t *out_len)
{
    TEE_Result ret = TEE_ERROR_GENERIC;
    uint32_t ramdisk_buf_len = ramdisk_cfg.block_size * ramdisk_cfg.block_count;

    if (!buf_out || !out_len) {
        ZF_LOGF("ERROR: Invalid parameters");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Allocate buffer for ramdisk.
     *
     * copied from littlefs/bd/lfs_rambd.c: lfs_rambd_create()
     */

    rambd_ctx.buffer = calloc(1, ramdisk_buf_len);
    if (!rambd_ctx.buffer) {
        ZF_LOGE("ERROR: out of memory");
        ret = TEE_ERROR_OUT_OF_MEMORY;
        goto out;
    }

    ret = lfs_format(fs_handle, &ramdisk_cfg);
    if (ret) {
        ZF_LOGF("ERROR: %d", ret);
        goto out;
    }

    ret = lfs_mount(fs_handle, &ramdisk_cfg);
    if (ret) {
        ZF_LOGF("ERROR: %d", ret);
        goto out;
    }

    *buf_out = rambd_ctx.buffer;
    *out_len = ramdisk_buf_len;

out:
    if (ret)
        free(rambd_ctx.buffer);

    return ret;
}

    ret = lfs_format(fs_handle, &ramdisk_cfg);
    if (ret) {
        ZF_LOGF("ERROR: %d", ret);
        return ret;
    }

    ret = lfs_mount(fs_handle, &ramdisk_cfg);
    if (ret) {
        ZF_LOGF("ERROR: %d", ret);
        return ret;
    }

    return ret;
}