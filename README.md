A simple kernel module to monitor LAN clients bandwidth usage

Display like this:

```sh
root@OpenWrt:~# bwt
IP              | DOWN  | UP    | ID             | VENDOR               | CONN | PKTS   | UPLOAD
192.168.1.122   | 0     | 0     | android-xxxxxx | Xiaomi Technology Co | 7    | 505    | 46KB
192.168.1.226   | 0     | 0     | MI2S-xx_xm     | XIAOMI CORPORATION   | 11   | 688    | 96KB
192.168.1.103   | 0     | 0     | xxxx-xxx       | Tenda Technology Co. | 14   | 2602   | 938KB
192.168.1.162   | 25    | 12    | android-xxxxxx | OnePlus Tech (Shenzh | 8    | 60379  | 25796KB
total           | 25    | 12    |                |                      | 40   |        | 
```
