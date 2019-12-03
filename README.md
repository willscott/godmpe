GoDmPe
=====

GoDmPe (Pronounced Go Dump PE) is a tool for dumping windbg memory dumps into a Portable Executible (PE) format.

The windbg dump provides regions of virtual address space, but is not structured in a way to be directly analyzable by executible debugging tools.

The program restructures a dump back into the memory space specified in a portable executible format so that standard windows debugging tools can analyze the program.

Usage
----

```
godmpe mem.dmp template.exe out.exe
```

This will take a memory dump (`mem.dmp`) of `template.exe` and apply the runtime setting ofm emory to the memory space specified by `template.exe`, written to `out.exe`.

`out.exe` can then be analyzed by ghidra or IDA.
