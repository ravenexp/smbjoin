Offline Windows AD domain join tool for Samba
=============================================

Implements a custom `smb-net-ads-join` utility, which performs the same
operation as `net ads join` Samba command, but works completely offline.

To join a Samba system to an AD domain it needs `SYSTEM`, `SECURITY` and `SAM`
registry hive files from a Windows system that is already joined to
the same domain.

Usage
-----

```
usage: smb-net-ads-join [-h] [-v] [-V] [-J] [-o FILE] DIR

positional arguments:
  DIR                   Windows registry hive files directory (e.g. '/Windows/System32/config')

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         print intermediate results and debug info
  -V, --version         show program's version number and exit
  -J, --json            generate 'secrets.json' file in place of 'secrets.tdb'
  -o FILE, --output FILE
                        generated 'secrets.tdb' file name and location
```
