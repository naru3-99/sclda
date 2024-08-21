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
