#include <net/sclda.h>
#include <stdio.h>

int hinagata() {
    int retval;
    int msg_len;
    char *msg_buf;

    retval = __sys_listen(fd, backlog);
    if (!is_sclda_allsend_fin()) return retval;

    // 送信するパート
    msg_len = 200;
    msg_buf = kmalloc(msg_len, GFP_KERNEL);
    if (!msg_buf) return retval;

    msg_len = snprintf(msg_buf, msg_len, "50%c%d%c%d%c%d", SCLDA_DELIMITER,
                       retval, SCLDA_DELIMITER, fd, SCLDA_DELIMITER, backlog);
    sclda_send_syscall_info(msg_buf, msg_len);
    return retval;
}

int filename() {
    int retval;
    int msg_len, path_len;
    char *msg_buf, *path_buf;

    retval = do_mkdirat(AT_FDCWD, getname(pathname), mode);
    if (!is_sclda_allsend_fin()) return retval;

    // ファイル名を取得する
    path_len = strnlen_user(pathname, PATH_MAX);
    path_buf = kmalloc(path_len + 1, GFP_KERNEL);
    if (!path_buf) return retval;
    if (copy_from_user(path_buf, pathname, path_len)) {
        memset(path_buf, 0, path_len + 1);
        path_len = 0;
    } else {
        path_buf[path_len] = '\0';
    }

    // 送信するパート
    msg_len = 100 + path_len;
    msg_buf = kmalloc(msg_len, GFP_KERNEL);
    if (!msg_buf) goto free_path;

    msg_len = snprintf(msg_buf, msg_len, "83%c%d%c%hu%c%s", SCLDA_DELIMITER,
                       retval, SCLDA_DELIMITER, (unsigned short)mode,
                       SCLDA_DELIMITER, path_buf);
    sclda_send_syscall_info(msg_buf, msg_len);

free_path:
    kfree(path_buf);
    return retval;
}

SYSCALL_DEFINE2(link, const char __user *, oldname, const char __user *,
                newname) {
    int retval;
    int msg_len, old_len, new_len;
    char *msg_buf, *old_buf, *new_buf;

    retval =
        do_linkat(AT_FDCWD, getname(oldname), AT_FDCWD, getname(newname), 0);
    if (!is_sclda_allsend_fin()) return retval;

    // oldnameを取得する
    old_len = strnlen_user(oldname, old_MAX);
    old_buf = kmalloc(old_len + 1, GFP_KERNEL);
    if (!old_buf) return retval;
    if (copy_from_user(old_buf, oldname, old_len)) goto free_old;
    old_buf[old_len] = '\0';

    // newnameを取得する
    new_len = strnlen_user(newname, new_MAX);
    new_buf = kmalloc(new_len + 1, GFP_KERNEL);
    if (!new_buf) goto free_old;
    if (copy_from_user(new_buf, newname, new_len)) goto free_new;
    new_buf[new_len] = '\0';

    // 送信するパート
    msg_len = 100 + old_len + new_len;
    msg_buf = kmalloc(msg_len, GFP_KERNEL);
    if (!msg_buf) goto free_new;

    msg_len =
        snprintf(msg_buf, msg_len, "86%c%d%c%s%c%s", SCLDA_DELIMITER, retval,
                 SCLDA_DELIMITER, old_buf, SCLDA_DELIMITER, new_buf);
    sclda_send_syscall_info(msg_buf, msg_len);

free_new:
    kfree(new_buf);
free_old:
    kfree(old_buf);
    return retval;
}