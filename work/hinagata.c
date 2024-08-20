#include <net/sclda.h>
#include <stdio.h>

SYSCALL_DEFINE1(dup, unsigned int, fildes) {
    int retval;
    struct sclda_iov siov;

    retval = sclda_dup(fildes);
    if (!is_sclda_allsend_fin()) return retval;

    siov.len = 100;
    siov.str = kmalloc(siov.len, GFP_KERNEL);
    if (!(siov.str)) return retval;

    siov.len = snprintf(siov.str, siov.len, "32%c%d%c%u", SCLDA_DELIMITER,
                        retval, SCLDA_DELIMITER, fildes);

    sclda_send_syscall_info(siov.str, siov.len);
    return retval;
}

SYSCALL_DEFINE2(access, const char __user *, filename, int, mode) {
    long retval;
    int msg_len, path_len;
    char *msg_buf, *path_buf;
    int written, path_ok;

    retval = do_faccessat(AT_FDCWD, filename, mode, 0);
    if (!is_sclda_allsend_fin()) return retval;

    path_len = strnlen_user(filename, PATH_MAX);
    path_buf = kmalloc(path_len + 1, GFP_KERNEL);
    if (!path_buf) {
        path_ok = 0;
        path_len = 0;
        goto sclda_all;
    }

    path_ok = 1;
    if (copy_from_user(path_buf, filename, path_len)) {
        memset(path_buf, 0, path_len + 1);
        path_len = 0;
    } else {
        path_buf[path_len] = '\0';
    }

sclda_all:
    msg_len = 100 + path_len;
    msg_buf = kmalloc(msg_len, GFP_KERNEL);
    if (!msg_buf) goto free_path;

    written = snprintf(msg_buf, msg_len, "21%c%ld%c%u", SCLDA_DELIMITER, retval,
                       SCLDA_DELIMITER, mode);
    if (path_ok)
        written += snprintf(msg_buf + written, msg_len - written, "%c%s",
                            SCLDA_DELIMITER, path_buf);
    sclda_send_syscall_info(msg_buf, written);

free_path:
    if (path_ok) kfree(path_buf);
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

int get_sigset_t(void){
    sigset_len = snprintf(sigset_buf, sclda_sigbufsize, "[");
    for (int i = 1; i < _NSIG; i++)
        if (sigismember(&set, i))
            sigset_len += snprintf(sigset_buf + sigset_len,
                                   sclda_sigbufsize - sigset_len, "%d,", i);
    sigset_len +=
        snprintf(sigset_buf + sigset_len, sclda_sigbufsize - sigset_len, "]");
}

SYSCALL_DEFINE4(rt_sigtimedwait) {

    struct sclda_iov siov;
    int retval = -EINVAL;
    int these_ok = 0, ts_ok = 0, info_ok = 0;
    size_t written = 0;

    if (!is_sclda_allsend_fin()) return retval;

    siov.len = 500;
    siov.str = kmalloc(siov.len, GFP_KERNEL);
    if (!(siov.str)) return retval;

    written = snprintf(siov.str, siov.len, "128%c%d%c%zu", SCLDA_DELIMITER,
                       retval, SCLDA_DELIMITER, sigsetsize);

    if (these_ok && siov.len > written) {
        written += snprintf(siov.str + written, siov.len - written, "%c%lu",
                            SCLDA_DELIMITER, these);
    } else {
        written += snprintf(siov.str + written, siov.len - written, "%cNULL",
                            SCLDA_DELIMITER);
    }
    sclda_send_syscall_info(siov.str, siov.len);
    return retval;
}