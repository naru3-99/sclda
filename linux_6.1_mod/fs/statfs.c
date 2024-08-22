// SPDX-License-Identifier: GPL-2.0
#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/statfs.h>
#include <linux/security.h>
#include <linux/uaccess.h>
#include <linux/compat.h>
#include <net/sclda.h>
#include "internal.h"

static int flags_by_mnt(int mnt_flags)
{
	int flags = 0;

	if (mnt_flags & MNT_READONLY)
		flags |= ST_RDONLY;
	if (mnt_flags & MNT_NOSUID)
		flags |= ST_NOSUID;
	if (mnt_flags & MNT_NODEV)
		flags |= ST_NODEV;
	if (mnt_flags & MNT_NOEXEC)
		flags |= ST_NOEXEC;
	if (mnt_flags & MNT_NOATIME)
		flags |= ST_NOATIME;
	if (mnt_flags & MNT_NODIRATIME)
		flags |= ST_NODIRATIME;
	if (mnt_flags & MNT_RELATIME)
		flags |= ST_RELATIME;
	if (mnt_flags & MNT_NOSYMFOLLOW)
		flags |= ST_NOSYMFOLLOW;
	return flags;
}

static int flags_by_sb(int s_flags)
{
	int flags = 0;
	if (s_flags & SB_SYNCHRONOUS)
		flags |= ST_SYNCHRONOUS;
	if (s_flags & SB_MANDLOCK)
		flags |= ST_MANDLOCK;
	if (s_flags & SB_RDONLY)
		flags |= ST_RDONLY;
	return flags;
}

static int calculate_f_flags(struct vfsmount *mnt)
{
	return ST_VALID | flags_by_mnt(mnt->mnt_flags) |
	       flags_by_sb(mnt->mnt_sb->s_flags);
}

static int statfs_by_dentry(struct dentry *dentry, struct kstatfs *buf)
{
	int retval;

	if (!dentry->d_sb->s_op->statfs)
		return -ENOSYS;

	memset(buf, 0, sizeof(*buf));
	retval = security_sb_statfs(dentry);
	if (retval)
		return retval;
	retval = dentry->d_sb->s_op->statfs(dentry, buf);
	if (retval == 0 && buf->f_frsize == 0)
		buf->f_frsize = buf->f_bsize;
	return retval;
}

int vfs_get_fsid(struct dentry *dentry, __kernel_fsid_t *fsid)
{
	struct kstatfs st;
	int error;

	error = statfs_by_dentry(dentry, &st);
	if (error)
		return error;

	*fsid = st.f_fsid;
	return 0;
}
EXPORT_SYMBOL(vfs_get_fsid);

int vfs_statfs(const struct path *path, struct kstatfs *buf)
{
	int error;

	error = statfs_by_dentry(path->dentry, buf);
	if (!error)
		buf->f_flags = calculate_f_flags(path->mnt);
	return error;
}
EXPORT_SYMBOL(vfs_statfs);

int user_statfs(const char __user *pathname, struct kstatfs *st)
{
	struct path path;
	int error;
	unsigned int lookup_flags = LOOKUP_FOLLOW | LOOKUP_AUTOMOUNT;
retry:
	error = user_path_at(AT_FDCWD, pathname, lookup_flags, &path);
	if (!error) {
		error = vfs_statfs(&path, st);
		path_put(&path);
		if (retry_estale(error, lookup_flags)) {
			lookup_flags |= LOOKUP_REVAL;
			goto retry;
		}
	}
	return error;
}

int fd_statfs(int fd, struct kstatfs *st)
{
	struct fd f = fdget_raw(fd);
	int error = -EBADF;
	if (f.file) {
		error = vfs_statfs(&f.file->f_path, st);
		fdput(f);
	}
	return error;
}

static int do_statfs_native(struct kstatfs *st, struct statfs __user *p)
{
	struct statfs buf;

	if (sizeof(buf) == sizeof(*st))
		memcpy(&buf, st, sizeof(*st));
	else {
		memset(&buf, 0, sizeof(buf));
		if (sizeof buf.f_blocks == 4) {
			if ((st->f_blocks | st->f_bfree | st->f_bavail |
			     st->f_bsize | st->f_frsize) &
			    0xffffffff00000000ULL)
				return -EOVERFLOW;
			/*
			 * f_files and f_ffree may be -1; it's okay to stuff
			 * that into 32 bits
			 */
			if (st->f_files != -1 &&
			    (st->f_files & 0xffffffff00000000ULL))
				return -EOVERFLOW;
			if (st->f_ffree != -1 &&
			    (st->f_ffree & 0xffffffff00000000ULL))
				return -EOVERFLOW;
		}

		buf.f_type = st->f_type;
		buf.f_bsize = st->f_bsize;
		buf.f_blocks = st->f_blocks;
		buf.f_bfree = st->f_bfree;
		buf.f_bavail = st->f_bavail;
		buf.f_files = st->f_files;
		buf.f_ffree = st->f_ffree;
		buf.f_fsid = st->f_fsid;
		buf.f_namelen = st->f_namelen;
		buf.f_frsize = st->f_frsize;
		buf.f_flags = st->f_flags;
	}
	if (copy_to_user(p, &buf, sizeof(buf)))
		return -EFAULT;
	return 0;
}

static int do_statfs64(struct kstatfs *st, struct statfs64 __user *p)
{
	struct statfs64 buf;
	if (sizeof(buf) == sizeof(*st))
		memcpy(&buf, st, sizeof(*st));
	else {
		memset(&buf, 0, sizeof(buf));
		buf.f_type = st->f_type;
		buf.f_bsize = st->f_bsize;
		buf.f_blocks = st->f_blocks;
		buf.f_bfree = st->f_bfree;
		buf.f_bavail = st->f_bavail;
		buf.f_files = st->f_files;
		buf.f_ffree = st->f_ffree;
		buf.f_fsid = st->f_fsid;
		buf.f_namelen = st->f_namelen;
		buf.f_frsize = st->f_frsize;
		buf.f_flags = st->f_flags;
	}
	if (copy_to_user(p, &buf, sizeof(buf)))
		return -EFAULT;
	return 0;
}

int statfs_to_str(const struct statfs __user *user_statfs, char *buf,
		  int buf_size)
{
	struct statfs kstatfs;
	// ユーザ空間からカーネル空間に構造体をコピー
	if (copy_from_user(&kstatfs, user_statfs, sizeof(struct statfs)))
		return -EFAULT;

	// 構造体のメンバを1度のsnprintfでバッファに書き込む
	return snprintf(buf, buf_size,
			"%ld%c%ld%c%ld%c"
			"%ld%c%ld%c%ld%c"
			"%ld%c%d%c%d%c"
			"%ld%c%ld%c%ld%c"
			"%ld%c%ld%c%ld%c%ld",
			kstatfs.f_type, SCLDA_DELIMITER, kstatfs.f_bsize,
			SCLDA_DELIMITER, kstatfs.f_blocks, SCLDA_DELIMITER,
			kstatfs.f_bfree, SCLDA_DELIMITER, kstatfs.f_bavail,
			SCLDA_DELIMITER, kstatfs.f_files, SCLDA_DELIMITER,
			kstatfs.f_ffree, SCLDA_DELIMITER, kstatfs.f_fsid.val[0],
			SCLDA_DELIMITER, kstatfs.f_fsid.val[1], SCLDA_DELIMITER,
			kstatfs.f_namelen, SCLDA_DELIMITER, kstatfs.f_frsize,
			SCLDA_DELIMITER, kstatfs.f_flags, SCLDA_DELIMITER,
			kstatfs.f_spare[0], SCLDA_DELIMITER, kstatfs.f_spare[1],
			SCLDA_DELIMITER, kstatfs.f_spare[2], SCLDA_DELIMITER,
			kstatfs.f_spare[3]);
}

SYSCALL_DEFINE2(statfs, const char __user *, pathname, struct statfs __user *,
		buf)
{
	struct kstatfs st;
	int retval;
	int msg_len, path_len, struct_len;
	char *msg_buf, *path_buf, *struct_buf;

	retval = user_statfs(pathname, &st);
	if (!retval)
		retval = do_statfs_native(&st, buf);

	if (!is_sclda_allsend_fin())
		return retval;

	// ファイル名を取得する
	path_len = strnlen_user(pathname, PATH_MAX);
	path_buf = kmalloc(path_len + 1, GFP_KERNEL);
	if (!path_buf)
		return retval;
	if (copy_from_user(path_buf, pathname, path_len))
		goto free_path;
	path_buf[path_len] = '\0';

	// ユーザ空間の構造体を取得する
	struct_len = 300;
	struct_buf = kmalloc(struct_len, GFP_KERNEL);
	if (!struct_buf)
		goto free_path;
	struct_len = statfs_to_str(buf, struct_buf, struct_len);
	if (struct_len < 0)
		goto free_struct_buf;

	// 送信するパート
	msg_len = 100 + path_len + struct_len;
	msg_buf = kmalloc(msg_len, GFP_KERNEL);
	if (!msg_buf)
		goto free_struct_buf;

	msg_len = snprintf(msg_buf, msg_len,
			   "137%c%d%c%s"
			   "%c%s",
			   SCLDA_DELIMITER, retval, SCLDA_DELIMITER, path_buf,
			   SCLDA_DELIMITER, struct_buf);
	sclda_send_syscall_info(msg_buf, msg_len);

free_struct_buf:
	kfree(struct_buf);
free_path:
	kfree(path_buf);
	return retval;
}

SYSCALL_DEFINE3(statfs64, const char __user *, pathname, size_t, sz,
		struct statfs64 __user *, buf)
{
	struct kstatfs st;
	int error;
	if (sz != sizeof(*buf))
		return -EINVAL;
	error = user_statfs(pathname, &st);
	if (!error)
		error = do_statfs64(&st, buf);
	return error;
}

SYSCALL_DEFINE2(fstatfs, unsigned int, fd, struct statfs __user *, buf)
{
	struct kstatfs st;
	int error = fd_statfs(fd, &st);
	if (!error)
		error = do_statfs_native(&st, buf);
	return error;
}

SYSCALL_DEFINE3(fstatfs64, unsigned int, fd, size_t, sz,
		struct statfs64 __user *, buf)
{
	struct kstatfs st;
	int error;

	if (sz != sizeof(*buf))
		return -EINVAL;

	error = fd_statfs(fd, &st);
	if (!error)
		error = do_statfs64(&st, buf);
	return error;
}

static int vfs_ustat(dev_t dev, struct kstatfs *sbuf)
{
	struct super_block *s = user_get_super(dev, false);
	int err;
	if (!s)
		return -EINVAL;

	err = statfs_by_dentry(s->s_root, sbuf);
	drop_super(s);
	return err;
}

SYSCALL_DEFINE2(ustat, unsigned, dev, struct ustat __user *, ubuf) {
    struct sclda_iov siov;
    size_t written = 0;

    int err, retval, tmp_ok;
    struct ustat tmp;
    struct kstatfs sbuf;
    tmp_ok = 0;

    err = vfs_ustat(new_decode_dev(dev), &sbuf);
    retval = err;
    if (err) goto out;

    memset(&tmp, 0, sizeof(struct ustat));
    tmp.f_tfree = sbuf.f_bfree;
    if (IS_ENABLED(CONFIG_ARCH_32BIT_USTAT_F_TINODE))
        tmp.f_tinode = min_t(u64, sbuf.f_ffree, UINT_MAX);
    else
        tmp.f_tinode = sbuf.f_ffree;
    tmp_ok = 1;

    retval = copy_to_user(ubuf, &tmp, sizeof(struct ustat)) ? -EFAULT : 0;

out:
    if (!is_sclda_allsend_fin()) return retval;

    siov.len = 500;
    siov.str = kmalloc(siov.len, GFP_KERNEL);
    if (!(siov.str)) return retval;

    written = snprintf(siov.str, siov.len, "136%c%d%c%u", SCLDA_DELIMITER,
                       retval, SCLDA_DELIMITER, dev);
    if (siov.len > written) {
        if (tmp_ok) {
            written +=
                snprintf(siov.str + written, siov.len - written,
                         "%c[%d,%lu,%s,%s]", SCLDA_DELIMITER, (int)tmp.f_tfree,
                         tmp.f_tinode, tmp.f_fname, tmp.f_fpack);
        } else {
            written += snprintf(siov.str + written, siov.len - written,
                                "%c[NULL]", SCLDA_DELIMITER);
        }
    }

    sclda_send_syscall_info(siov.str, written);
    return retval;
}

#ifdef CONFIG_COMPAT
static int put_compat_statfs(struct compat_statfs __user *ubuf,
			     struct kstatfs *kbuf)
{
	struct compat_statfs buf;
	if (sizeof ubuf->f_blocks == 4) {
		if ((kbuf->f_blocks | kbuf->f_bfree | kbuf->f_bavail |
		     kbuf->f_bsize | kbuf->f_frsize) &
		    0xffffffff00000000ULL)
			return -EOVERFLOW;
		/* f_files and f_ffree may be -1; it's okay
		 * to stuff that into 32 bits */
		if (kbuf->f_files != 0xffffffffffffffffULL &&
		    (kbuf->f_files & 0xffffffff00000000ULL))
			return -EOVERFLOW;
		if (kbuf->f_ffree != 0xffffffffffffffffULL &&
		    (kbuf->f_ffree & 0xffffffff00000000ULL))
			return -EOVERFLOW;
	}
	memset(&buf, 0, sizeof(struct compat_statfs));
	buf.f_type = kbuf->f_type;
	buf.f_bsize = kbuf->f_bsize;
	buf.f_blocks = kbuf->f_blocks;
	buf.f_bfree = kbuf->f_bfree;
	buf.f_bavail = kbuf->f_bavail;
	buf.f_files = kbuf->f_files;
	buf.f_ffree = kbuf->f_ffree;
	buf.f_namelen = kbuf->f_namelen;
	buf.f_fsid.val[0] = kbuf->f_fsid.val[0];
	buf.f_fsid.val[1] = kbuf->f_fsid.val[1];
	buf.f_frsize = kbuf->f_frsize;
	buf.f_flags = kbuf->f_flags;
	if (copy_to_user(ubuf, &buf, sizeof(struct compat_statfs)))
		return -EFAULT;
	return 0;
}

/*
 * The following statfs calls are copies of code from fs/statfs.c and
 * should be checked against those from time to time
 */
COMPAT_SYSCALL_DEFINE2(statfs, const char __user *, pathname,
		       struct compat_statfs __user *, buf)
{
	struct kstatfs tmp;
	int error = user_statfs(pathname, &tmp);
	if (!error)
		error = put_compat_statfs(buf, &tmp);
	return error;
}

COMPAT_SYSCALL_DEFINE2(fstatfs, unsigned int, fd, struct compat_statfs __user *,
		       buf)
{
	struct kstatfs tmp;
	int error = fd_statfs(fd, &tmp);
	if (!error)
		error = put_compat_statfs(buf, &tmp);
	return error;
}

static int put_compat_statfs64(struct compat_statfs64 __user *ubuf,
			       struct kstatfs *kbuf)
{
	struct compat_statfs64 buf;

	if ((kbuf->f_bsize | kbuf->f_frsize) & 0xffffffff00000000ULL)
		return -EOVERFLOW;

	memset(&buf, 0, sizeof(struct compat_statfs64));
	buf.f_type = kbuf->f_type;
	buf.f_bsize = kbuf->f_bsize;
	buf.f_blocks = kbuf->f_blocks;
	buf.f_bfree = kbuf->f_bfree;
	buf.f_bavail = kbuf->f_bavail;
	buf.f_files = kbuf->f_files;
	buf.f_ffree = kbuf->f_ffree;
	buf.f_namelen = kbuf->f_namelen;
	buf.f_fsid.val[0] = kbuf->f_fsid.val[0];
	buf.f_fsid.val[1] = kbuf->f_fsid.val[1];
	buf.f_frsize = kbuf->f_frsize;
	buf.f_flags = kbuf->f_flags;
	if (copy_to_user(ubuf, &buf, sizeof(struct compat_statfs64)))
		return -EFAULT;
	return 0;
}

int kcompat_sys_statfs64(const char __user *pathname, compat_size_t sz,
			 struct compat_statfs64 __user *buf)
{
	struct kstatfs tmp;
	int error;

	if (sz != sizeof(*buf))
		return -EINVAL;

	error = user_statfs(pathname, &tmp);
	if (!error)
		error = put_compat_statfs64(buf, &tmp);
	return error;
}

COMPAT_SYSCALL_DEFINE3(statfs64, const char __user *, pathname, compat_size_t,
		       sz, struct compat_statfs64 __user *, buf)
{
	return kcompat_sys_statfs64(pathname, sz, buf);
}

int kcompat_sys_fstatfs64(unsigned int fd, compat_size_t sz,
			  struct compat_statfs64 __user *buf)
{
	struct kstatfs tmp;
	int error;

	if (sz != sizeof(*buf))
		return -EINVAL;

	error = fd_statfs(fd, &tmp);
	if (!error)
		error = put_compat_statfs64(buf, &tmp);
	return error;
}

COMPAT_SYSCALL_DEFINE3(fstatfs64, unsigned int, fd, compat_size_t, sz,
		       struct compat_statfs64 __user *, buf)
{
	return kcompat_sys_fstatfs64(fd, sz, buf);
}

/*
 * This is a copy of sys_ustat, just dealing with a structure layout.
 * Given how simple this syscall is that apporach is more maintainable
 * than the various conversion hacks.
 */
COMPAT_SYSCALL_DEFINE2(ustat, unsigned, dev, struct compat_ustat __user *, u)
{
	struct compat_ustat tmp;
	struct kstatfs sbuf;
	int err = vfs_ustat(new_decode_dev(dev), &sbuf);
	if (err)
		return err;

	memset(&tmp, 0, sizeof(struct compat_ustat));
	tmp.f_tfree = sbuf.f_bfree;
	tmp.f_tinode = sbuf.f_ffree;
	if (copy_to_user(u, &tmp, sizeof(struct compat_ustat)))
		return -EFAULT;
	return 0;
}
#endif
