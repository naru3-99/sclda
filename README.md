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
  - OS から必要な情報を UDP 通信を用いて送信
- [sclda_host](https://github.com/naru3-99/sclda_host)：
  - ホスト環境で使用する、UDP パケットを受信するサーバ
- [sclda_guest](https://github.com/naru3-99/sclda_guest):
  - ゲスト環境で、解析したいプログラムを別プロセスで実行

## UDP パケットの中身

全ての情報は、\x05 区切りになっている。

- pid(システムコールを呼び出したプロセス ID)
- sched_clock(ナノ秒:カーネルの起動後に経過した時間を示す)
- syscall_msg(syscall_info.csv を参照。システムコールごとに異なる)
  - システムコールの情報として取得したかったが、時間的制約により取得できなかったものについて、[SCLDA_TODO.md](./SCLDA_TODO.md)に記述した

## 過去レポジトリとの関係

[ICAART(国際学会)に提出した論文](https://www.insticc.org/node/TechnicalProgram/ICAART/2024/presentationDetails/123729)に乗せるため、未完成の状態のシステムを public レポジトリとして公開しています。

過去のレポジトリ：対応する現在のレポジトリ

- [sct_debian](https://github.com/naru3-99/sct_debian)：sclda(本レポジトリ)
- [langMorphDA](https://github.com/naru3-99/langMorphDA)：[sclda_host](https://github.com/naru3-99/sclda_host) , [sclda_guest](https://github.com/naru3-99/sclda_guest)
