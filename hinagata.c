#include <stdio.h>

int hinagata()
{
    if (!is_sclda_allsend_fin())
        return retval;

    // 送信するパート
    int msg_len = 200;
    char *msg_buf = kmalloc(msg_len, GFP_KERNEL);
    if (!msg_buf)
        return retval;

    msg_len = snprintf(msg_buf, msg_len, "99999%c%d%c%u", SCLDA_DELIMITER,
                       retval, SCLDA_DELIMITER, fd);
    sclda_send_syscall_info(msg_buf, msg_len);
    return retval;
}

int filename()
{
    // ファイル名を取得する
    int filename_len = strnlen_user(filename, 1000);
    char *filename_buf = kmalloc(filename_len + 1, GFP_KERNEL);
    if (!filename_buf)
        return retval;
    filename_len -= copy_from_user(filename_buf, filename, filename_len);
    filename_buf[filename_len] = '\0';
}

int struct_to_str()
{
    int struct_len = 200;
    char *struct_buf = kmalloc(struct_len, GFP_KERNEL);
    if (!struct_buf)
        return retval;
    struct_len =
        __kernel_old_itimerval_to_str(value, struct_buf, struct_len);
    if (struct_len < 0)
    {
        struct_len = 1;
        struct_buf = "\0";
    }
}