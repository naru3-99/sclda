/*
 * udp.c
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

int init_sclda_client_udp(struct sclda_client_struct *sclda_cs_ptr, int port) {
    int retval;
    if (sclda_cs_ptr == NULL) return -EFAULT;

    // create socket
    retval = sock_create_kern(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_UDP,
                              &(sclda_cs_ptr->sock));
    if (retval < 0)
        printk(KERN_ERR
               "SCLDA_ERR init_sclda_client_udp socket_create, port = %d",
               port);

    // setting for ipv4 udp communication
    sclda_cs_ptr->addr.sin_family = PF_INET;
    sclda_cs_ptr->addr.sin_port = htons(port);
    sclda_cs_ptr->addr.sin_addr.s_addr = htonl(SCLDA_SERVER_IP);

    // setting for msghdr struct
    sclda_cs_ptr->hdr.msg_name = &(sclda_cs_ptr->addr);
    sclda_cs_ptr->hdr.msg_namelen = sizeof(struct sockaddr_in);
    sclda_cs_ptr->hdr.msg_control = NULL;
    sclda_cs_ptr->hdr.msg_controllen = 0;
    sclda_cs_ptr->hdr.msg_flags = 0;
    sclda_cs_ptr->hdr.msg_control_is_user = false;
    sclda_cs_ptr->hdr.msg_get_inq = false;
    sclda_cs_ptr->hdr.msg_iocb = NULL;
    sclda_cs_ptr->hdr.msg_ubuf = NULL;

    // init mutex
    mutex_init(&sclda_cs_ptr->mtx);
    return 0;
}