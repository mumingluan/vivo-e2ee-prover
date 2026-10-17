# vivo E2EE Prover

调整 vivo VMS 的风险输入与信用评分返回值，并兼容云空间过长的存储标识。

VMS 中处理的输入是调试标志、开发者选项、root adbd 和 Frida socket。授权调用方读取评分时返回 `3`，随后仍通过官方任务执行本地计算和云端同步。云空间中超过 64 字符的十六进制存储标识会转为稳定的 MD5 摘要。

## 使用

安装 APK，在 LSPosed 中启用，作用域选 `com.vivo.vms` 和 `com.bbk.cloud`，然后重新启动相应宿主进程。模块没有桌面界面。

返回分数不等于改变硬件可信状态，也不能保证服务器接受请求。存储标识变化可能被云端视为另一台备份设备。停用后，下次宿主启动会恢复原行为。

## 构建

Windows、Python 3、JDK 21、Android SDK platform 36、build-tools 36.1.0。设置 `JAVA_HOME` 和 `ANDROID_HOME`，运行 `python build.py`。Xposed API 82 会从官方仓库下载并核对摘要，只用于编译。

默认使用本机 Android debug keystore；私钥不随源码提供。使用自己的密钥构建，不能直接覆盖其他签名的 APK。

## 许可证

原有代码采用 GPL-3.0-only，Copyright (C) 2026 Axuan。第三方代码遵循各自许可证，见 [THIRD_PARTY.md](THIRD_PARTY.md)。

版本 `1.7`，包名 / 模块 ID：`com.axuan.vivoe2eeprover`。
