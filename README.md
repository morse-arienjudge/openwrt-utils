# OpenWrt Utilities

This repository might one day be a collection of utilities structured in an OpenWrt feed, which otherwise have no home.

## Usage

To add the packages in this repository to your OpenWrt build root, append the following line to your OpenWrt feeds.conf file.
```
src-git utils https://github.com/morse-arienjudge/openwrt-utils
```

Update your OpenWrt feed and install all packages to your package index
```
./scripts/feeds update utils
./scripts/feeds install -p utils -a
```

Run `make menuconfig` and select the packages you require. For example, `PACKAGE_ocs`.

Compile an individual package with
```
make package/<folder_name>/compile V=sc 2>&1 | tee log.txt
```

or just build an entire image with `make`.

## License

Metadata and some source files within this repository are licensed under GNU General Public License version 3.0. Some of the packages may rely on source code which falls under a different license, or otherwise specify something alternative.

Inspect each package for licenses used.