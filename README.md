# FortiObfuscate CLI

Fortinet Federal Tool to utilize consistent replacement across multiple different files (and file types). 

## Dependencies

dpkt, binaryornot

```
pip install dpkt binaryornot
```

## Usage

To run the program, you simply need to run it with a directory as its only argument:

```
py fobf.py <directory> [optional options]
```

The specified directory must contain the following subdirectories corresponding to the file format of the files within:

'configs' = place FortiGate configuration files\
'pcaps' = place pcap files\
'syslogs' = place syslog files\
'fedwalk' = place other files that need to be scrubbed

Any files in any other subdirectory (or at the top level) will be exempted from obfuscation.

## New Features

- Now supports multiprocessing to cut down on runtime. Currently, it only affects files that are marked under fedwalk. By default, spawns 4 child processes on runtime, and can be changed with the --override=<num_procs> CLI arg, which is detailed in the -h output as well.
  - Seeing a little over 50% reduction in time spent running with 4 child processes. Diminishing returns are expected around 8 spawned processes

## Why aren't all sensitive values getting scrubbed?

This is best explained with what each menu option does

config, syslog, pcap: These sub-programs depend on standardized context to grab (specifically) string values. Fields in syslog-formatted files can include user=<username>, devid=1234, etc. This makes the string values easier to grab and replace

fedwalk: this program specifically only looks for ip address patterns, and will replace any strings that have been cached by the previously mentioned programs. If you are only using 'fedwalk' on all your files, it will not replace any sensitive string values.

### Bringing both program types together

There is now an option dubbed 'Aggressive' mode which affects files in the configs, syslogs, and pcaps folders. After an initial, normal passthrough of these files with the corresponding subroutines, the program will feed the obfuscated outputs into the fedwalk program to *potentially* catch any lines that may have been missed.