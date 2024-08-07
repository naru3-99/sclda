#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <string.h>

int main() {
    // まず、サンプルデータを書き込むファイルを作成
    int fd = open("example_preadv2.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    // 書き込みデータを準備
    const char *data = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    write(fd, data, strlen(data));
    close(fd);

    // ファイルを読み込み用にオープン
    fd = open("example_preadv2.txt", O_RDONLY);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    // バッファを3つ用意
    char buf1[10];
    char buf2[10];
    char buf3[10];

    // iovec構造体を設定
    struct iovec iov[3];
    iov[0].iov_base = buf1;
    iov[0].iov_len = sizeof(buf1);
    iov[1].iov_base = buf2;
    iov[1].iov_len = sizeof(buf2);
    iov[2].iov_base = buf3;
    iov[2].iov_len = sizeof(buf3);

    // preadv2を呼び出し、ファイルのオフセット10からデータを読み込む
    off_t offset = 10;
    int flags = 0; // 例えば RWF_HIPRI を指定することができる
    ssize_t nread = preadv2(fd, iov, 3, offset, flags);
    if (nread == -1) {
        perror("preadv2");
        close(fd);
        exit(EXIT_FAILURE);
    }

    // 読み込んだデータのサイズを出力
    printf("Read %zd bytes from offset %ld.\n", nread, offset);

    // 各バッファの内容を表示
    printf("Buffer 1: %.*s\n", (int)iov[0].iov_len, (char *)iov[0].iov_base);
    printf("Buffer 2: %.*s\n", (int)iov[1].iov_len, (char *)iov[1].iov_base);
    printf("Buffer 3: %.*s\n", (int)iov[2].iov_len, (char *)iov[2].iov_base);

    // ファイルをクローズ
    close(fd);

    return 0;
}
