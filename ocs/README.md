# Morse Micro Off Channel Scan

This utility performs an off channel scan on a Morse Micro chip and reports the measured RX time, listen time and noise for the given channel.

## Disclaimer

This tool is for education purposes only and demonstrates the use of netlink to ineract with the  Morse Micro OCS vendor command.

This tool is not thoroughly tested and significant liberties have been taken regarding error handling and input data validation; in favour of keeping the rest of the source code as clear as possible. As-is, this tool is not recommended for production.

## Compiling

See feed instructions for compiling with OpenWrt.

No instructions are provided for compiling outside of the OpenWrt buildroot. However, `src/Makefile` should be reasonably portable.

# Usage
```
ocs <interface> <frequency> <bandwidth> <primary width> <primary index>
```

For example
```
ocs wlan0 922000 8 2 2
```

## License

GNU General Public License version 3.0