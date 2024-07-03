// SPDX-License-Identifier: GPL-2.0
/*
 * Supplementary group IDs
 */
#include <linux/cred.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/security.h>
#include <linux/sort.h>
#include <linux/syscalls.h>
#include <linux/user_namespace.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <net/sclda.h>

struct group_info *groups_alloc(int gidsetsize)
{
	struct group_info *gi;
	gi = kvmalloc(struct_size(gi, gid, gidsetsize), GFP_KERNEL_ACCOUNT);
	if (!gi)
		return NULL;

	atomic_set(&gi->usage, 1);
	gi->ngroups = gidsetsize;
	return gi;
}

EXPORT_SYMBOL(groups_alloc);

void groups_free(struct group_info *group_info)
{
	kvfree(group_info);
}

EXPORT_SYMBOL(groups_free);

/* export the group_info to a user-space array */
static int groups_to_user(gid_t __user *grouplist,
			  const struct group_info *group_info)
{
	struct user_namespace *user_ns = current_user_ns();
	int i;
	unsigned int count = group_info->ngroups;

	for (i = 0; i < count; i++) {
		gid_t gid;
		gid = from_kgid_munged(user_ns, group_info->gid[i]);
		if (put_user(gid, grouplist + i))
			return -EFAULT;
	}
	return 0;
}

/* fill a group_info from a user-space array - it must be allocated already */
static int groups_from_user(struct group_info *group_info,
			    gid_t __user *grouplist)
{
	struct user_namespace *user_ns = current_user_ns();
	int i;
	unsigned int count = group_info->ngroups;

	for (i = 0; i < count; i++) {
		gid_t gid;
		kgid_t kgid;
		if (get_user(gid, grouplist + i))
			return -EFAULT;

		kgid = make_kgid(user_ns, gid);
		if (!gid_valid(kgid))
			return -EINVAL;

		group_info->gid[i] = kgid;
	}
	return 0;
}

static int gid_cmp(const void *_a, const void *_b)
{
	kgid_t a = *(kgid_t *)_a;
	kgid_t b = *(kgid_t *)_b;

	return gid_gt(a, b) - gid_lt(a, b);
}

void groups_sort(struct group_info *group_info)
{
	sort(group_info->gid, group_info->ngroups, sizeof(*group_info->gid),
	     gid_cmp, NULL);
}
EXPORT_SYMBOL(groups_sort);

/* a simple bsearch */
int groups_search(const struct group_info *group_info, kgid_t grp)
{
	unsigned int left, right;

	if (!group_info)
		return 0;

	left = 0;
	right = group_info->ngroups;
	while (left < right) {
		unsigned int mid = (left + right) / 2;
		if (gid_gt(grp, group_info->gid[mid]))
			left = mid + 1;
		else if (gid_lt(grp, group_info->gid[mid]))
			right = mid;
		else
			return 1;
	}
	return 0;
}

/**
 * set_groups - Change a group subscription in a set of credentials
 * @new: The newly prepared set of credentials to alter
 * @group_info: The group list to install
 */
void set_groups(struct cred *new, struct group_info *group_info)
{
	put_group_info(new->group_info);
	get_group_info(group_info);
	new->group_info = group_info;
}

EXPORT_SYMBOL(set_groups);

/**
 * set_current_groups - Change current's group subscription
 * @group_info: The group list to impose
 *
 * Validate a group subscription and, if valid, impose it upon current's task
 * security record.
 */
int set_current_groups(struct group_info *group_info)
{
	struct cred *new;
	const struct cred *old;
	int retval;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	old = current_cred();

	set_groups(new, group_info);

	retval = security_task_fix_setgroups(new, old);
	if (retval < 0)
		goto error;

	return commit_creds(new);

error:
	abort_creds(new);
	return retval;
}

EXPORT_SYMBOL(set_current_groups);

int sclda_getgroups(int gidsetsize, gid_t __user *grouplist)
{
	const struct cred *cred = current_cred();
	int i;

	if (gidsetsize < 0)
		return -EINVAL;

	/* no need to grab task_lock here; it cannot change */
	i = cred->group_info->ngroups;
	if (gidsetsize) {
		if (i > gidsetsize) {
			i = -EINVAL;
			goto out;
		}
		if (groups_to_user(grouplist, cred->group_info)) {
			i = -EFAULT;
			goto out;
		}
	}
out:
	return i;
}

SYSCALL_DEFINE2(getgroups, int, gidsetsize, gid_t __user *, grouplist)
{
	int retval;
	int msg_len, group_len;
	char *msg_buf, *group_buf;
	int i, written;
	gid_t *kgl;

	retval = sclda_getgroups(gidsetsize, grouplist);
	if (!is_sclda_allsend_fin())
		return retval;

	// grouplistの中身を取得する
	group_len = 30 * ((retval < 0) ? 1 : retval); // 1 groupidにつき30で十分
	group_buf = kmalloc(group_len, GFP_KERNEL);
	if (!group_buf)
		return retval;

	if (retval < 0)
		goto no_info;
	if (gidsetsize < 0)
		goto no_info;
	if (!grouplist)
		goto no_info;

	// grouplistをカーネルにコピーする
	kgl = kmalloc_array(retval, sizeof(gid_t), GFP_KERNEL);
	if (!kgl)
		goto free_buf;

	if (copy_from_user(kgl, grouplist, sizeof(gid_t) * retval))
		goto no_info;

	// バッファに情報を書き込む
	written = 0;
	for (i = 0; i < retval; i++)
		written += snprintf(group_buf + written, group_len - written,
				    "%u;", (unsigned int)kgl[i]);

	group_len = written;
	goto send_info;

no_info:
	group_len = 1;
	group_buf[0] = '\0';

send_info:
	// 送信するパート
	msg_len = 200 + group_len;
	msg_buf = kmalloc(msg_len, GFP_KERNEL);
	if (!msg_buf)
		goto free_kgl;

	msg_len = snprintf(msg_buf, msg_len, "115%c%d%c%d%c%s", SCLDA_DELIMITER,
			   retval, SCLDA_DELIMITER, gidsetsize, SCLDA_DELIMITER,
			   group_buf);
	sclda_send_syscall_info(msg_buf, msg_len);

free_kgl:
	kfree(kgl);
free_buf:
	kfree(group_buf);
	return retval;
}

bool may_setgroups(void)
{
	struct user_namespace *user_ns = current_user_ns();

	return ns_capable_setid(user_ns, CAP_SETGID) &&
	       userns_may_setgroups(user_ns);
}

/*
 *	SMP: Our groups are copy-on-write. We can set them safely
 *	without another task interfering.
 */

int sclda_setgroups(int gidsetsize, gid_t __user *grouplist)
{
	struct group_info *group_info;
	int retval;

	if (!may_setgroups())
		return -EPERM;
	if ((unsigned)gidsetsize > NGROUPS_MAX)
		return -EINVAL;

	group_info = groups_alloc(gidsetsize);
	if (!group_info)
		return -ENOMEM;
	retval = groups_from_user(group_info, grouplist);
	if (retval) {
		put_group_info(group_info);
		return retval;
	}

	groups_sort(group_info);
	retval = set_current_groups(group_info);
	put_group_info(group_info);

	return retval;
}

SYSCALL_DEFINE2(setgroups, int, gidsetsize, gid_t __user *, grouplist)
{
	int retval;
	int msg_len, group_len;
	char *msg_buf, *group_buf;
	int i, written;
	gid_t *kgl;

	retval = sclda_setgroups(gidsetsize, grouplist);
	if (!is_sclda_allsend_fin())
		return retval;

	// grouplistの中身を取得する
	group_len =
		30 *
		((gidsetsize < 0) ? 1 : gidsetsize); // 1 groupidにつき30で十分
	group_buf = kmalloc(group_len, GFP_KERNEL);
	if (!group_buf)
		return retval;

	if (gidsetsize < 0)
		goto no_info;
	if (retval < 0)
		goto no_info;
	if (!grouplist)
		goto no_info;

	kgl = kmalloc_array(gidsetsize, sizeof(gid_t), GFP_KERNEL);
	if (!kgl)
		goto free_groupbuf;

	if (copy_from_user(kgl, grouplist, sizeof(gid_t) * gidsetsize))
		goto no_info;

	written = 0;
	for (i = 0; i < gidsetsize; i++)
		written += snprintf(group_buf + written, group_len - written,
				    "%u;", (unsigned int)kgl[i]);

	group_len = written;
	goto send_info;

no_info:
	group_len = 1;
	group_buf[0] = '\0';

send_info:
	// 送信するパート
	msg_len = 200 + group_len;
	msg_buf = kmalloc(msg_len, GFP_KERNEL);
	if (!msg_buf)
		goto free_kgl;

	msg_len = snprintf(msg_buf, msg_len, "116%c%d%c%d%c%s", SCLDA_DELIMITER,
			   retval, SCLDA_DELIMITER, gidsetsize, SCLDA_DELIMITER,
			   group_buf);
	sclda_send_syscall_info(msg_buf, msg_len);

free_kgl:
	kfree(kgl);
free_groupbuf:
	kfree(group_buf);
	return retval;
}

/*
 * Check whether we're fsgid/egid or in the supplemental group..
 */
int in_group_p(kgid_t grp)
{
	const struct cred *cred = current_cred();
	int retval = 1;

	if (!gid_eq(grp, cred->fsgid))
		retval = groups_search(cred->group_info, grp);
	return retval;
}

EXPORT_SYMBOL(in_group_p);

int in_egroup_p(kgid_t grp)
{
	const struct cred *cred = current_cred();
	int retval = 1;

	if (!gid_eq(grp, cred->egid))
		retval = groups_search(cred->group_info, grp);
	return retval;
}

EXPORT_SYMBOL(in_egroup_p);
