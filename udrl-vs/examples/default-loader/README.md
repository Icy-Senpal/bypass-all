# Default Loader Example

This is a simple loader based upon Stephen Fewer's original code. It can be compiled as a prepended "Double Pulsar" style loader 
or a stomped "Stephen Fewer" style loader.

**Note:** This project builds a "Double Pulsar" style loader by default. As a result, it is important to increase the "stage size" 
when generating artifacts via the Arsenal kit.

## Quick Start Guide

To get started, use the instructions provided below.

### Debug Build

To start Debugging:
* Start the teamserver with the `example.profile` in the project directory.
* Export a RAW Beacon payload from the teamserver (our Debug DLL).
* Add the DLL to the project - `py.exe .\udrl.py xxd <path\to\beacon_x64.bin> .\library\DebugDLL.x64.h`.
* Start the Visual Studio Debugger (make sure to right-click default-loader in the
Solution Explorer->Set As Startup Project).

### Release Build

There are two versions of the Release build in the default-loader example:
* `Default`  creates a "Double Pulsar" style loader that should be 'prepended' to Beacon. 
* `Stephen_Fewer` creates a "Stephen Fewer" style loader that should be 'stomped' into Beacon. 

For more information on these different approaches see - https://cobaltstrike.com/blog/revisiting-the-udrl-part-1-simplifying-development 

To use either of the Release builds:
* Start the teamserver with the `example.profile` in the project directory (and export a beacon payload for testing).
* Compile the `Release` build.
  * [Optional] To build the `STEPHEN_FEWER` version, uncomment the `#define _STEPHEN_FEWER` macro in `ReflectiveLoader.cpp`.
* Test the loader (the below example is for x64):
	* `Default` - `py.exe .\udrl.py prepend-udrl <path\to\beacon_x64.bin> bin\default-loader\Release\x64\default-loader.x64.exe`
	* `STEPHEN_FEWER` - `py.exe .\udrl.py stomp-udrl <path\to\beacon_x64.bin> bin\default-loader\Release\x64\default-loader.x64.exe`
* Load (`bin/default-loader/prepend-udrl.cna` | `bin/default-loader/stomp-udrl.cna`) to Cobalt Strike.
* Export a Beacon payload.
  * Modify "stage size" if using "Double Pulsar" style and Cobalt Strike's default shellcode runners/the artifact kit.

**Note:** Make sure to use the 32-bit version of Python when testing the x86 builds!

## Additional Considerations

As part of the quick start guide, we provided `example.profile` to get you up
and running. This is a simple profile based upon a public example to avoid
any issues.

You will undoubtedly want to use your own profiles and make modifications to
Beacon. It is therefore important to note that only the communication elements
of a given C2 profile (HTTP/HTTPs/DNS etc) will be applied to a Beacon 
exported via one of the BEACON_RDLL_GENERATE* hooks. You are expected to apply 
PE modifications to a Beacon exported via one of the BEACON_RDLL_GENERATE* 
hooks using Aggressor Functions. 

For example, to mask a given section of Beacon:

```
$payload = pe_mask_section($beacon, ".text", <XORkey>);
```

In addition, to apply the contents of the transform blocks and setup any strings
specified in the C2 profile:

```
$payload = setup_reflective_loader($beacon, $ldr);
$payload = setup_strings($payload);
$payload = setup_transformations($payload, $arch);
```
The above is demonstrated in the obfuscation-loader example.

## Modifications

You're encouraged to make modifications to this code and use them in your
engagements. Do not redistribute this source code. It is not open source. It
is provided as a benefit to licensed Cobalt Strike users.

## License

This code is subject to the end user license agreement for Cobalt Strike. The
complete license agreement is at:

https://www.cobaltstrike.com/license

This code is subject to the license for the Reflective loader project by
Stephen Fewer. The complete license is at:

https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/LICENSE.txt
