# Process Inject Kit

Process injection is a core component to Cobalt Strike post exploitation.
Until now, the option was to use a built-in injection technique using fork&run.
This has been great for stability, but does come at the cost of OPSEC.

Cobalt Strike 4.5 now supports two new Aggressor Script hooks
`PROCESS_INJECT_SPAWN` and `PROCESS_INJECT_EXPLICIT`.  These hooks allow
a user to define how the fork&run and explicit injection techniques are
implemented when executing post-exploitation commands instead of using
the built-in techniques. 

The implementation of these techniques is through a Beacon Object File (BOF)
and an Aggressor Script function.

These two hooks will cover most of the post exploitation commands, which
will be listed in each section.  However, here are some exceptions which
will not use these hooks. 

#### Exceptions
Beacon Command 	 | Aggressor Script function 
-----------------|--------------------------
N/A              | &bdllspawn  
execute-assembly | &bexecute_assembly 
shell	         | &bshell

## References

- https://www.cobaltstrike.com/blog/process-injection-update-in-cobalt-strike-4-5/
- https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_hooks.htm#PROCESS_INJECT_EXPLICIT
- https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_hooks.htm#PROCESS_INJECT_SPAWN

## How it works

The built in fork and run process injection techniques can be change with
the `PROCESS_INJECT_SPAWN` and `PROCESS_INJECT_EXPLICIT` hooks.

This kit provides the following: 
- source code to implement the built-in techniques via a BOF
- aggressor script template to implement the hooks
- build script to compile and generate a distribution directory


#### PROCESS_INJECT_SPAWN

Hook to allow users to define how the fork and run process injection technique
is implemented when executing post exploitation commands using a Beacon Object
File (BOF).


#### PROCESS_INJECT_EXPLICIT

Hook to allow users to define how the explicit process injection technique is
implemented when executing post exploitation commands using a Beacon Object
File (BOF).

# Usage

```
./build.sh <output directory>
```

# Load into Cobalt Strike

To use the Process inject Kit, load the processinject.cna into Cobalt Strike.

Open the Scripts manager, Cobalt Strike -> Scripts

Load `<output directory>/process_inject/processinject.cna`

# Modifications

You're encouraged to make modifications to this code and use them in your
engagements.

# License

This code is not subject to the end user license agreement for Cobalt Strike.
