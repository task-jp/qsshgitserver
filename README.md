# qsshgitserver

## Requirements

- Qt 5.12 or later
- [WolfSSH](https://www.wolfssl.com/products/wolfssh/) 1.3.0

## Build
```
$ qmake "LIBS+=-L/path/to/wolfssl/lib -lwolfssl -L/path/to/wolfssh/lib -lwolfssh" "INCLUDEPATH+=/path/to/wolfssl/include /path/to/local/wolfssh/include"
$ make
```

## Run

Run the binary in a directory that contains git bare repositories

```
$ export PUBLIC_KEY="ssh-rsa AAA...AAA taskjp@aaa"
$ /path/to/qsshgitserver
```

## Test

```
$ git clone ssh://localhost:22222/test.git
```
