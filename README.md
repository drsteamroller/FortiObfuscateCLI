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

## Why aren't all sensitive values getting scrubbed?

This is best explained with what each menu option does

config, syslog, pcap: These sub-programs depend on standardized context to grab (specifically) string values. Fields in syslog-formatted files can include user=<username>, devid=1234, etc. This makes the string values easier to grab and replace

fedwalk: this program specifically only looks for ip address patterns, and will replace any strings that have been cached by the previously mentioned programs. If you are only using 'fedwalk' on all your files, it will not replace any sensitive string values.