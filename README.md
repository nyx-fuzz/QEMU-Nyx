# QEMU-NYX

This repository contains Nyx's fork of QEMU. To enable Hypervisor based snapshots, Intel-PT based tracing, and REDQUEEN style magic byte resolution, we made various extensions to QEMU. This includes the ability to quickly reset memory and devices, obtain precise disassembly of the code running (even when code is partially swapped out / unavailable) & Intel-PT decoding, instrument code running in the VM with breakpoint-based hooks as well as communicating with a fuzzing frontend (e.g. based on [libnyx](https://github.com/nyx-fuzz/libnyx)).

You can find more detailed information in our main repository.

<p>
<img align="right" width="200"  src="logo.png">
</p>

## Build

```
./compile_qemu_nyx.sh lto
```

## Bug Reports and Contributions

If you found and fixed a bug on your own: We are very open to patches, please create a pull request!  

### License

This tool is provided under **GPLv2 license**. 

**Free Software Hell Yeah!** 

Proudly provided by: 
* [Sergej Schumilo](http://schumilo.de) - sergej@schumilo.de / [@ms_s3c](https://twitter.com/ms_s3c)
* [Cornelius Aschermann](https://hexgolems.com) - cornelius@hexgolems.com / [@is_eqv](https://twitter.com/is_eqv)
