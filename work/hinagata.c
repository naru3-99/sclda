#include <net/sclda.h>

int dup(unsigned int fildes) {
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

int get_sigset_t(void){
        written += snprintf(siov.str + written, siov.len - written, "[");
        for (int i = 1; i < _NSIG; i++)
            if (sigismember(&temp, i))
                sigset_len += snprintf(siov.str + written, siov.len - written, "%d,", i);
        written += snprintf(siov.str + written, siov.len - written, "]");
}

SYSCALL_DEFINE2(utime, char __user *, filename, struct utimbuf __user *,
                times) {
    struct sclda_iov siov, path_iov;
    size_t written = 0;
    long retval = -EFAULT;
    struct timespec64 tv[2];
    int tvok = 0;

    if (times) {
        if (get_user(tv[0].tv_sec, &times->actime) ||
            get_user(tv[1].tv_sec, &times->modtime))
            goto out;
        tv[0].tv_nsec = 0;
        tv[1].tv_nsec = 0;
        tvok = 1;
    }

    retval = do_utimes(AT_FDCWD, filename, times ? tv : NULL, 0);

out:
    if (!is_sclda_allsend_fin()) return retval;

    siov.len = 500;
    siov.str = kmalloc(siov.len, GFP_KERNEL);
    if (!(siov.str)) return retval;

    written = snprintf(siov.str, siov.len, "132%c%ld", SCLDA_DELIMITER, retval);
    if (siov.len > written) {
        if (tvok) {
            written += snprintf(siov.str + written, siov.len - written,
                                "%c[%lld,%ld][%lld,%ld]", SCLDA_DELIMITER,
                                (long long)tv[0].tv_sec, tv[0].tv_nsec,
                                (long long)tv[1].tv_sec, tv[1].tv_nsec);
        } else {
            written += snprintf(siov.str + written, siov.len - written,
                                "%c[NULL][NULL]", SCLDA_DELIMITER);
        }
    }

    path_iov.len = strnlen_user(filename, PATH_MAX);
    if (siov.len < written + path_iov.len) goto send_info;

    path_iov.str = kmalloc(path_iov.len + 1, GFP_KERNEL);
    if (!path_iov.str) goto give_up;
    if (copy_from_user(path_iov.str, filename, path_iov.len)) {
        kfree(path_iov.str);
        goto give_up;
    }
    written += snprintf(siov.str + written, siov.len - written, "%c%s",
                        SCLDA_DELIMITER, path_iov.str);
    kfree(path_iov.str);
    goto send_info;

give_up:
    written += snprintf(siov.str + written, siov.len - written, "%cNULL",
                        SCLDA_DELIMITER);
send_info:
    sclda_send_syscall_info(siov.str, written);
    return retval;
}


SYSCALL_DEFINE1(chroot, const char __user *, filename) {
    struct sclda_iov siov, path_iov;
    int retval;
    long temp;

    retval = sclda_chroot(filename);
    if (!is_sclda_allsend_fin()) return retval;

    temp = strnlen_user(filename, PATH_MAX);
    if (temp > 0) {
        path_iov.len = temp;
    } else {
        path_iov.len = 0;
        goto gather_info;
    }

    path_iov.str = kmalloc(path_iov.len + 1, GFP_KERNEL);
    if (!path_iov.str) goto gather_info;
    if (copy_from_user(path_iov.str, filename, path_iov.len)) {
        path_iov.len = 0;
        kfree(path_iov.str);
    }

gather_info:
    siov.len = 100 + path_iov.len;
    siov.str = kmalloc(siov.len, GFP_KERNEL);
    if (!(siov.str)) {
        if (path_iov.len != 0) kfree(path_iov.str);
        return retval
    };

    written = snprintf(siov.str, siov.len, "161%c%d", SCLDA_DELIMITER, retval);
    if (siov.len > written) {
        if (path_iov.len == 0) {
            written += snprintf(siov.str + written, siov.len - written,
                                "%cNULL", SCLDA_DELIMITER);
        } else {
            written += snprintf(siov.str + written, siov.len - written, "%c%s",
                                SCLDA_DELIMITER, path_iov.str);
            kfree(path_iov.str);
        }
    }
    sclda_send_syscall_info(siov.str, written);
    return retval;
}