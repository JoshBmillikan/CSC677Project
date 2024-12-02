A packet capture and inspection tool

uses Qt and libpcap
```
sudo apt install qt6-base-dev
```

libpcap is provided as a git submodule, clone with ```--recursive``` to ensure it is installed 


The project is built with cmake

https://cmake.org/cmake/help/latest/index.html

The executable must be run with root permissions to capture packets, only linux is supported
