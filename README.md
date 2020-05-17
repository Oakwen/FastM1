# About FastM1

![c language](https://img.shields.io/badge/language-c-blue.svg)    [![libnfc](https://img.shields.io/librariesio/release/homebrew/libnfc/1.7.1)](https://github.com/nfc-tools/libnfc)    [![Build Status](https://travis-ci.org/Oakwen/fastm1.svg)](https://travis-ci.org/Oakwen/fastm1)

快速读写M1卡内容，方便快速初始化卡片。

Requirements

==================

Some NFC drivers depend on third party software:

* libnfc [libnfc-1.7.1](https://github.com/nfc-tools/libnfc)

* pn53x_usb & acr122_usb [libusb-0.1](http://libusb.sf.net)

* acr122_pcsc [pcsc-lite](http://pcsclite.alioth.debian.org/)

* pcsc Support build with pcsc driver, which can be using all compatible readers, Feitian R502 and bR500 already passed the test.
