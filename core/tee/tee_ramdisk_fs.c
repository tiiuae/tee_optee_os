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

static lfs_t lfs_ramdisk = { 0 };
static lfs_t *fs_handle = &lfs_ramdisk;

static lfs_rambd_t rambd_ctx = { 0 };

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

    ret = lfs_file_open(fs_handle, file_handle, po->obj_id, lfs_flags);
    if (ret) {
        EMSG("ERROR: %d: %s", ret, (char*)po->obj_id);
        return lsfs_err_to_tee_res(ret);
    }

    ret = lfs_file_size(fs_handle, file_handle);
    if (ret < 0) {
        EMSG("ERROR: %d: %s", ret, (char*)po->obj_id);
        lfs_file_close(fs_handle, file_handle);
        free(file_handle);
        return lsfs_err_to_tee_res(ret);
    }

    *size = ret;

    *fh = (struct tee_file_handle *)file_handle;

    IMSG("%s: handle: %p, size: %ld", (char*)po->obj_id, file_handle, *size);

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

    ret = lfs_file_open(fs_handle, file_handle, po->obj_id, lfs_flags);
    if (ret) {
        EMSG("ERROR: %d: %s", ret, (char*)po->obj_id);
        goto out;
    }

    if (head && head_size) {
        ret = lfs_file_write(fs_handle, file_handle, head, head_size);
        if (ret < 0) {
            EMSG("ERROR: %d: %s", ret, (char*)po->obj_id);
            goto out_file_cleanup;
        }

        pos += ret;
    }

    if (attr && attr_size) {
        ret = lfs_file_write(fs_handle, file_handle, attr, attr_size);
        if (ret < 0) {
            EMSG("ERROR: %d: %s", ret, (char*)po->obj_id);
            goto out_file_cleanup;
        }

        pos += ret;
    }

    if (data && data_size) {
        ret = lfs_file_write(fs_handle, file_handle, data, data_size);
        if (ret < 0) {
            EMSG("ERROR: %d: %s", ret, (char*)po->obj_id);
            goto out_file_cleanup;
        }

        pos += ret;
    }

    ret = TEE_SUCCESS;

    *fh = (struct tee_file_handle *)file_handle;

    IMSG("%s: h: %p, p: %d", (char*)po->obj_id, file_handle, pos);

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

    ZF_LOGI("%s", (char*)po->obj_id);

    ret = lfs_remove(fs_handle, po->obj_id);
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

TEE_Result ramdisk_fs_init(void)
{
    TEE_Result ret = TEE_ERROR_GENERIC;

    ret = lfs_rambd_create(&ramdisk_cfg);
    if (ret) {
        ZF_LOGF("ERROR: %d", ret);
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