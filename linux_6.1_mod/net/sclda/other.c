/*
 * net/sclda/other.c
 * Copyright (C) [2023] [Naru3 (Narumi Yoneda)
 * (7423530@ed.tus.ac.jp,naru99yoneda@gmail.com)]
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301 USA.
 */

#include <net/sclda.h>

long copy_char_from_user_dinamic(char **dst, const char __user *src){
    long length;
    char *buf;

    if (src == NULL) return -EFAULT;

    length = strnlen_user(src, PATH_MAX);
    if (length <= 0) return -EFAULT;

    buf = kmalloc(length+1,GFP_KERNEL);
    if (!buf) return -ENOMEM;

    if (copy_from_user(buf, src, length)) {
        kfree(buf);
        return -EFAULT;
    }
    *dst = buf;
    return length;
};

int sclda_get_current_pid(void) {
    return (int)pid_nr(get_task_pid(current, PIDTYPE_PID));
}

int kernel_timespec_to_str(const struct __kernel_timespec __user *uptr,
                           char *msg_buf, int msg_len) {
    struct __kernel_timespec kptr;

    if (!uptr) return -EFAULT;

    if (copy_from_user(&kptr, uptr, sizeof(struct __kernel_timespec)))
        return -EFAULT;

    return snprintf(msg_buf, msg_len, "%lld%c%lld", kptr.tv_sec,
                    SCLDA_DELIMITER, kptr.tv_nsec);
}