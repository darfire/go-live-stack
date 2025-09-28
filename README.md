# live-stack

**live-stack** offers tools to resolve the stack trace of running Linux process, given the instruction pointers.

It leverages both the [/proc/pid/maps](https://www.kernel.org/doc/Documentation/filesystems/proc.txt) and the [ELF](https://refspecs.linuxfoundation.org/elf/elf.pdf) file format to resolve the symbols that the instruction pointers reference. The ELF files must not be stripped of their symbol tables.

## Why we need this

The Linux loader uses Address Space Layout Randomization (ASLR) to map the different sections of an executable at random addresses in the virtual memory. This means that the addresses of functions and variables are not fixed, and they change every time the program is run. Thus resolving the symbol that contain a certain memory address involves taking into account the processes memory layout.

You can obtain this information using gdb using the following command:
```
(gdb) info proc mappings
```

However, for programmatic use, you need to implement it yourself or use something like **live-stack**.

Personally, I use it to resolve stacks that I collect using EBPF probes.

## Usage

Build a process context:
```
ctx, err := NewProcessContext(pid)
if err != nil {
  // handle error
}
```

Resolve the stack trace:
```
frames := ctx.GetStackTrace(addresses)
```

## Contributing and improving

The interface to the library is simple, intuitive, and probably subject to changes. Feel free to open an issue or a pull request for any improvements.

## License

Licensed under the MIT License.