# sclda

System Call Level Dynamic Analysis

「任意のプログラムが実行した内容」を解析(データ化)するシステム

Author: Naru3

- 7423530(at)ed.tus.ac.jp
- naru99yoneda(at)gmail.com

## License

This project is licensed under the terms of the GNU General Public License v2.0. See the [LICENSE](./LICENSE) file for details.

## ライセンス

Linux Kernel 自体が GPL に従っているため、それを改変したレポジトリである sclda も GPL に従う。

## 構成

- sclda(本レポジトリ)：
  - debian linux のソースコードを改造して作成
  - virtual box による仮想環境でビルドし、使用
  - カーネルから情報を送信
- [sclda_host](https://github.com/naru3-99/sclda_host)：
  - ホスト環境で使用する、情報を受信し保存するサーバ

## how to build
```
sudo bash make.sh
```