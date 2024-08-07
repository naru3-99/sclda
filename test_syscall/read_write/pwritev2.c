#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <string.h>

int main() {
    // 書き込み用にファイルをオープン（存在しない場合は作成、存在する場合は上書き）
    int fd = open("example_pwritev2.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    // 書き込みデータを準備
    const char *buf1 = "Hello, ";
    const char *buf2 = "this is ";
    const char *buf3 = "a test using pwritev2.\n";

    // iovec構造体を設定
    struct iovec iov[3];
    iov[0].iov_base = (void *)buf1;
    iov[0].iov_len = strlen(buf1);
    iov[1].iov_base = (void *)buf2;
    iov[1].iov_len = strlen(buf2);
    iov[2].iov_base = (void *)buf3;
    iov[2].iov_len = strlen(buf3);

    // pwritev2を呼び出し、ファイルのオフセット0からデータを書き込む
    off_t offset = 0;
    int flags = RWF_DSYNC; // 例えば RWF_DSYNC を指定
    ssize_t nwritten = pwritev2(fd, iov, 3, offset, flags);
    if (nwritten == -1) {
        perror("pwritev2");
        close(fd);
        exit(EXIT_FAILURE);
    }

    // 書き込んだデータのサイズを出力
    printf("Wrote %zd bytes.\n", nwritten);

    // ファイルをクローズ
    close(fd);

    return 0;
}
