# HD100 开源固件

华大 HD-100 带屏密码键盘双界面读卡器(STM32F103RBT6)的替换固件，用 Rust + [embassy](https://embassy.dev) 编写。
把原厂私有 HID 协议换成标准 **USB CCID**,接上 pcscd / Windows 智能卡服务即可直接使用，无需厂商驱动。

硬件资料(引脚、各芯片的行为与坑点)见 [docs/hardware.md](docs/hardware.md)。

## 功能

USB 复合设备 `1209:0003`(pid.codes 测试 PID,仅供开发):

| 接口 | 功能 |
|---|---|
| CCID "Contactless" | 非接 THM3060:ISO 14443 A/B、ISO-DEP、Mifare Classic(PC/SC 伪 APDU 认证 / 读写)、NTAG |
| HID 键盘 | 磁条 2、3 轨，刷卡后以 `;2轨?;3轨?` + 回车键入 |
| CCID "Contact" | 正面接触卡座,ISO 7816 T=0(GPIO 模拟),支持 PPS / 特定模式，短 APDU |

- 蜂鸣器：接触卡正确插入(有 ATR)滴一声；非接卡放上、拿走各滴一声。
- 键盘：已驱动，目前只输出日志。屏、字库、PSAM 座 2–5:驱动已有，尚未接入主机接口。

## 构建与烧录

```sh
cd firmware
cargo build --release
cargo run --release          # probe-rs 烧录并显示 defmt 日志
```

- 需要 `thumbv7m-none-eabi` 目标与 [probe-rs](https://probe.rs)。
- 原厂固件开了读保护并关闭 SWD:首次烧录需 BOOT0 接 3.3V 进系统 bootloader,
  或用 connect-under-reset;解除读保护会整片擦除。
- `--features mute`:开机让语音芯片保持复位，消除上电的"请插卡"。语音芯片占用 SWD 引脚，
  开启后 SWD 失效，之后只能经 BOOT0 重新烧录。

## 上位机

- Linux:`sudo python3 tools/add_libccid.py && sudo systemctl restart pcscd`,把本设备加入 libccid 设备表。

## 已知限制

- 接触卡：只支持 T=0、短 APDU;无卡检测开关，靠周期性冷复位判断在位；PSAM 座 2/4/5 未实测，
  座 2–5 共用时钟，下电一个座会停其他座的时钟。
- 非接：未实现多卡防冲突；射频余量偏小。

## 许可

[GPL-3.0-or-later](LICENSE)。
