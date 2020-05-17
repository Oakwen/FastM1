# About FastM1

![c language](https://img.shields.io/badge/language-c-blue.svg)    [![libnfc](https://img.shields.io/librariesio/release/homebrew/libnfc/1.7.1)](https://github.com/nfc-tools/libnfc)    [![Build Status](https://travis-ci.org/Oakwen/fastm1.svg)](https://travis-ci.org/Oakwen/fastm1)

快速读写M1卡内容，方便快速初始化卡片。For my own use only!

***

用法：

在当前目录下新建文件```temp.dump```，内容为需要M1卡数据，方便快速初始化卡片。

***

依赖项：

本软件部分功能依赖与下列第三方文件:

* libnfc [libnfc-1.7.1](https://github.com/nfc-tools/libnfc)

* pn53x_usb & acr122_usb [libusb-0.1](http://libusb.sf.net)

* acr122_pcsc [pcsc-lite](http://pcsclite.alioth.debian.org/)
