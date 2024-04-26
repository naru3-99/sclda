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
    char *filename_buf = kmalloc(filename_len, GFP_KERNEL);
    if (!filename_buf)
        return retval;
    filename_len =
        (int)copy_from_user(filename_buf, filename, filename_len);
}