# User-Defined Reflective Loader Visual Studio (UDRL-VS)

This kit contains the User-Defined Reflective Loader Visual Studio (UDRL-VS) 
template. UDRL-VS is a library of functions to help support the development of reflective loaders. It is accompanied by two blog posts to explain the rationale behind it and introduce some key concepts. 

The posts can be found here:

* https://cobaltstrike.com/blog/revisiting-the-udrl-part-1-simplifying-development
* https://cobaltstrike.com/blog/revisiting-the-udrl-part-2-obfuscation-masking

The UDRL-VS kit is primarily intended to function as a library. However, the
`udrl-vs/examples` directory contains example loaders to demonstrate different
techniques. These examples have been briefly described below, and more information on how to use/debug them can be found in the README files - `/examples/<loader>/README.md`.

* `bud-loader` - a "Double Pulsar" style loader that shows how to pass additional data to a Beacon.
* `default-loader` - a simple reflective loader based upon Stephen Fewer's original. It can be compiled as a prepended "Double Pulsar" style loader or a stomped "Stephen Fewer" style loader.
* `obfuscation-loader` - a "Double Pulsar" style loader that uses a custom approach to obfuscation and masking.
* `postex-loader` - a "Double Pulsar" style loader for Post Exploitation DLLs.

## Prerequisites:

Required:

* An x64 Windows 10/11 development machine (without a security solution)
* Visual Studio Community/Pro/Enterprise 2022 (Desktop Development with C++ installed).
* Python3 (x64 v3.9+) - complete with the Python Launcher for Windows (`py.exe`).
* Python dependencies (`py.exe -m pip install -r requirements.txt`).
* A licensed teamserver.

Optional:

* Python3 (x86) - required to test x86 payloads (requires `pefile`).

**Note:** The Visual Studio project expects to use `py.exe`, which is the Python Launcher for Windows - https://docs.python.org/3/using/windows.html#launcher. This is installed by default by the Windows Python installer but the build will fail if this is not set up.

## Creating A Loader

To start from the beginning, and create a new loader:

* Open the udrl-vs.sln solution.
* Create a new project (File->New->Project).
  * Select C++ Console App.
  * Give the loader a name and under "Solution" make sure to select "Add to Solution".
* Add a reference to the UDRL-VS library.
  * Right click the new project->Add->Reference and check "library".
* Apply the provided properties file (`loader.prop`).
  * Open Visual Studio's Property Manager (the location can vary, use the search bar "Property Manager")
  * Right click the new project->Add Existing Property Sheet.
  * Add loader.prop to apply the required project settings.
* Add a Debug DLL to the project - `py.exe .\udrl.py xxd <path\to\beacon_x64.bin> .\library\DebugDLL.x64.h`
* Create a `ReflectiveLoader.cpp` source file and a `ReflectiveLoader.h` header.
* Begin Development.

## Additional Considerations

Please be aware of the following when developing UDRLs:
* Keep an eye on the Script Console, if the BEACON_RDLL_GENERATE* hooks fail,
the teamserver will output a default Beacon payload which can cause confusion.
* The teamserver needs to be able to parse Beacon in order to apply transformations.
Modify header values like `MZ`, `PE` and `e_lfanew` last after performing all 
other modifications.
* The `prepend` style loader will increase the size of Beacon. Be sure to account
for this when generating artifacts via the Arsenal kit.
* Developing PIC code can be challenging and difficult to Debug. For example, we experienced
crashes on x86 builds when upgrading from Visual Studio 17.9.x to 17.10.x due to optimization.
We wanted to highlight this issue as it may save you some time debugging.

## Sleep Mask

The Sleep Mask kit is an important aspect of Cobalt Strike's evasion strategy.
It is possible to use the Sleep Mask kit with a UDRL. However, it's important
to highlight some profile options that impact its operation.

The `obfuscate` flag does not obfuscate a Beacon with a UDRL
as you are expected to apply modifications via an Aggressor Script. However, 
setting  `obfuscate` to true will tell the Sleep Mask that the PE header was not
copied into the new memory allocation as part of loading Beacon (this is one 
of the transformations applied by the default loader). This means that your loader should not copy the PE header over either, otherwise it will not be masked.

In addition, `userwx` is set to true by default, therefore the Sleep Mask will expect Beacon memory to be RWX and attempt to perform it's normal masking 
operation on the .text section. In order to avoid RWX memory and use RX memory 
for the .text section, `userwx`should be set to false and `mask_text_section`
should be applied in the Sleep Mask kit.

## Handling a UDRL over 5k

The "Stephen Fewer" style loader is stomped into Beacon. As a result, it's important 
to consider its size. The default `stagesize` value supports a 5K reflective loader. 
However, an Aggressor Hook exists that can increase this to 100K.

```

# ------------------------------------
# $1 = DLL file name
# $2 = arch
# ------------------------------------
set BEACON_RDLL_SIZE {
   warn("Running 'BEACON_RDLL_SIZE' for DLL " . $1 . " with architecture " . $2);
   return "100";
}# ------------------------------------
```
--- 

## The UDRL-VS Template

This template is based on the classic reflective
loader by Stephen Fewer https://github.com/stephenfewer/ReflectiveDLLInjection. 
Modifications have been made to simplify it and remove unused code. 
New code has also been added to help simplify development and debugging.

## References

- Reflective DLL Injection by Stephen Fewer: https://github.com/stephenfewer/ReflectiveDLLInjection
- BokuLoader by Bobby Cooke and Santiago Pecin: https://github.com/boku7/BokuLoader
- AceLdr by Kyle Avery: https://github.com/kyleavery/AceLdr
- TitanLdr by Austin Hudson: https://github.com/realoriginal/titanldr-ng

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
