1. 系统检测到新版本之后，下载全量升级包。系统默认下载路径是.Ota
2. 下载好之后，手动进入twrp，手动刷入全量包，不需要任何清除操作
3. 此时进入系统，root权限被清除，twrp被替换。需要重新手动刷入
4. 手机USB连接电脑，电脑用==管理员==打开cmd
5. 找到adb命令，fastboot命令所在的目录
6. 设备重启到bootloader
```
adb reboot bootloader
```
7. fastboot检测设备
```
fastboot devices
```
8. fastboot刷入twrp
```
fastboot flash recovery twrp-x.x.x-x-oneplus3.img
```
9. 重启手机进入twrp，刷入Magisk卡刷包，重启结束。
