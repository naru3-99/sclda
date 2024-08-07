#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <string.h>

int main() {
    // ファイルを読み込み用にオープン
    int fd = open("example.txt", O_RDONLY);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    // バッファを3つ用意
    char buf1[10];
    char buf2[20];
    char buf3[30];

    // iovec構造体を設定
    struct iovec iov[3];
    iov[0].iov_base = buf1;
    iov[0].iov_len = sizeof(buf1);
    iov[1].iov_base = buf2;
    iov[1].iov_len = sizeof(buf2);
    iov[2].iov_base = buf3;
    iov[2].iov_len = sizeof(buf3);

    // readvを呼び出し、データを読み込む
    ssize_t nread = readv(fd, iov, 3);
    if (nread == -1) {
        perror("readv");
        close(fd);
        exit(EXIT_FAILURE);
    }

    // 読み込んだデータのサイズを出力
    printf("Read %zd bytes.\n", nread);

    // 各バッファの内容を表示
    printf("Buffer 1: %.*s\n", (int)iov[0].iov_len, (char *)iov[0].iov_base);
    printf("Buffer 2: %.*s\n", (int)iov[1].iov_len, (char *)iov[1].iov_base);
    printf("Buffer 3: %.*s\n", (int)iov[2].iov_len, (char *)iov[2].iov_base);

    // ファイルをクローズ
    close(fd);

    return 0;
}
