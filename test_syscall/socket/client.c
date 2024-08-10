#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};
    char *hello = "Hello from client";

    // ソケットファイルディスクリプタの作成
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // サーバーのIPアドレスを設定 (127.0.0.1はローカルホスト)
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    // サーバーに接続
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

    // サーバーにメッセージを送信
    send(sock, hello, strlen(hello), 0);
    printf("Hello message sent\n");

    // サーバーからのメッセージを受信
    read(sock, buffer, BUFFER_SIZE);
    printf("Message from server: %s\n", buffer);

    // ソケットをクローズ
    close(sock);

    return 0;
}
