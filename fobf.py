# fobf.py - Bringing it all together (CLI edition)
# Author - Andrew McConnell
# Date - 09/12/2023

import sys
import os
import re
import logging
import time
from binascii import hexlify, unhexlify

try:
    import tools.confsrb as conf
    import tools.fedwalk as fedwalk
    import tools.logscrub as log
    import tools.pcap_scrub as pcap
    import tools.regrepl as rr
except ImportError as e:
    print(f"You must download the entire package from GitHub, and download all dependencies:\n {e}")
    sys.exit()

ip_repl_mstr = {}
mac_repl_mstr = {}
str_repl_mstr = {}
og_workspace = ""
mod_workspace = ""
opflags = []
agg_fedwalk = False

debug_mode = False
# debug mode to be replaced: 
log_fn = "fortiobfuscate_debug.log"
log_lvl = logging.INFO
log_frmt = '%(levelname)s: %(message)s'

num_procs = 4

sysslash = '/'
# Gotta love Windows
if sys.platform == 'win32':
    sysslash = '\\'
ordered_rr = False
json_file = f".{sysslash}tools{sysslash}precons.json"
generic_rep = False
import_rr = {}

def importMap(filename : str):
    """
    Import mapping to populate str/ip/mac_repl_mstr dictionaries (usually from a previous run of this program)\\
    Params:\\
    filename : str of filename, which is opened and read by the function
    """
    lines = []
    with open(filename, 'r') as o:
        lines = o.readlines()

    # Flags that are set when we see certain lines (Strings, IP, MAC)
    imp_ip = False
    imp_mac = False
    imp_str = False

    for l in lines:
        if '>>>' in l:
            if 'IP' in l:
                imp_ip = True
                imp_mac = False
                imp_str = False
            elif 'MAC' in l:
                imp_ip = False
                imp_mac = True
                imp_str = False
            elif 'Strings' in l:
                imp_ip = False
                imp_mac = False
                imp_str = True
            else:
                print("Map file is improperly formatted, do not make changes to the map file unless you know what you are doing")
                sys.exit(1)
            continue
        
        # Skip this line if it is empty
        if not len(l):
            continue

        if imp_ip:
            components = l.split(' -> ')
            try:
                ip_repl_mstr[components[0]] = components[1]
            except:
                print(f"\nImproperly formatted line (or newline): {l}\n")
        elif imp_mac:
            components = l.split(' -> ')
            try:
                mac_repl_mstr[components[0]] = components[1]
            except:
                print(f"\nImproperly formatted line (or newline): {l}\n")
        elif imp_str:
            components = l.split(' -> ')
            try:
                str_repl_mstr[components[0]] = components[1]
            except:
                print(f"\nImproperly formatted line (or newline): {l}\n")
        
        else:
            print("Something went wrong, mappings might not be fully imported\n")
            print(f"Interpreted mappings based on import\n\
                  IP Mapping: {ip_repl_mstr}\n\
                  MAC Address Mapping: {mac_repl_mstr}\n\
                  String Mapping: {str_repl_mstr}\n")
    
    # Finally, we merge these imports with the subroutine replacement dictionaries
    set_repl_dicts()


def buildDirTree(dir):
    """
    Stages a target directory and gives us a tree structure representation of the top level directory\\
    Params:
    dir : string of the TLD, which is parsed by os.walk\\
    
    Returns:
    modified directory path + directory tree of the original
    """
    mod_dir = f"{dir}_obfuscated"

    mtd = mod_dir

    dirTree = next(os.walk(dir))[0]
    slashes = dirTree.count('/') + dirTree.count('\\')

    dirTree = []

    for dirpath, dirnames, fnames in os.walk(dir):
        check = f"{dirpath}"
        
        dirTree.append(check)

    # Create new directory to house the modified files
    os.makedirs(mod_dir, exist_ok=True)

    moddirTree = dirTree.copy()
    for i, path in enumerate(moddirTree):
        a = re.search(dir, path)
        moddirTree[i] = path[:a.span()[0]] + mod_dir + path[a.span()[1]:]

        os.makedirs(moddirTree[i], exist_ok=True)
    
    return (mtd, dirTree)

def getFiles(dirTree):
    """
    Takes the dirTree list of the buildDirTree function and siphons out the files, which we will then use to obfuscate\\
    Params:
    dirTree: os.walk list of directories and files in the top level directory supplied

    Returns:
    list of files in all directories inside the TLD including the top level directory
    """
    slash = '/'

    files = []
    # Gotta love Windows
    if sys.platform == 'win32':
        slash = '\\'
    
    # list comprehension ftw! dir + slash (/ or \) + filename
    for dir in dirTree:
        try:
            files.extend([f'{dir}{slash}{i}' for i in next(os.walk(dir))[2]])
            if f'{dir}{slash}{args[0]}' in files:
                print(f"\nERROR: You cannot perform fortiobfuscate on a directory containing itself\n\nexiting...\n")
                logging.critical("You cannot perform fortiobfuscate on a directory containing itself")
                sys.exit()
        except TypeError as e:
            print(f"Encountered {e} at directory {dir}")
    
    return files

def abbrevIP6(ip6):
    """
    FULL quartet (ffff, abcd, ad0c, f001) -> do nothing\\
    LEADING ZEROES (00ff, 0f01, 0001) -> chop them off\\
    ALL ZEROES -> kill all and adjacent all zero quartets and replace with ::
    """
    reconst = ""
    addColon = True
    for quartet in ip6.split(':'):
        if quartet == '0000':
            if addColon:
                reconst += ":"
                addColon = False
            continue

        zero = True
        re = ''
        for hex in quartet:
            if hex != '0':
                zero = False
            
            if not zero:
                re += hex
        quartet = re

        reconst += quartet + ':'
    
    return reconst[:-1]

# For when a map is imported
def set_repl_dicts():
    """
    Set the individual program replacement dictionaries to the master dictionaries
    """

    global ip_repl_mstr
    global mac_repl_mstr
    global str_repl_mstr

    log.ip_repl |= ip_repl_mstr
    conf.ip_repl |= ip_repl_mstr
    fedwalk.ip_repl |= ip_repl_mstr

    log.str_repl |= str_repl_mstr
    conf.str_repl |= str_repl_mstr
    fedwalk.str_repl |= str_repl_mstr

    fedwalk.mac_repl |= mac_repl_mstr

    pcap.ipswap |= ip_repl_mstr
    pcap.strswap |= str_repl_mstr
    #toPCAPFormat()

# Grabs the replacement dicts from the sub-programs and appends them to the mstr dicts
def append_mstr_dicts():
    """
    Append new findings to our master dictionaries from the individual program dictionaries\\
    This is done after the obfuscation function is performed on a file
    """

    global ip_repl_mstr
    global mac_repl_mstr
    global str_repl_mstr

    if log.ip_repl:
        ip_repl_mstr = ip_repl_mstr | log.ip_repl
    if conf.ip_repl:
        ip_repl_mstr = ip_repl_mstr | conf.ip_repl
    if fedwalk.ip_repl:
        ip_repl_mstr = ip_repl_mstr | fedwalk.ip_repl
    if log.str_repl:
        str_repl_mstr = str_repl_mstr | log.str_repl
    if conf.str_repl:
        str_repl_mstr = str_repl_mstr | conf.str_repl
    if fedwalk.str_repl:
        str_repl_mstr = str_repl_mstr | fedwalk.str_repl
    if fedwalk.mac_repl:
        mac_repl_mstr = mac_repl_mstr | fedwalk.mac_repl

    if pcap.ipswap:
        ip_repl_mstr = ip_repl_mstr | pcap.ipswap
    if pcap.strswap:
        str_repl_mstr = str_repl_mstr | pcap.strswap

    #fromPCAPFormat()

def print_mstr_dicts():

    print("IP replacement master dict")
    print(ip_repl_mstr)
    print("STR replacement master dict")
    print(str_repl_mstr)
    print("MAC replacement master dict")
    print(mac_repl_mstr)

def print_child_proc_dicts():

    print("Order is always: conf, syslog, pcap, fedwalk")
    print("IP replacement child dicts")
    print(conf.ip_repl)
    print(log.ip_repl)
    print(pcap.ip_repl)
    print(fedwalk.ip_repl)
    print("STR replacement child dicts")
    print(conf.str_repl)
    print(log.str_repl)
    print(pcap.str_repl)
    print(fedwalk.str_repl)

def clear_non_fedwalk_repl_dicts():

    del pcap.ipswap
    del pcap.strswap
    
    del log.ip_repl
    del log.str_repl
    
    del conf.ip_repl
    del conf.str_repl

def sync_fedwalk_mstr_dicts():

    global ip_repl_mstr
    global mac_repl_mstr
    global str_repl_mstr

    ip_repl_mstr = ip_repl_mstr | fedwalk.ip_repl
    str_repl_mstr = str_repl_mstr | fedwalk.str_repl
    mac_repl_mstr = mac_repl_mstr | fedwalk.mac_repl

    fedwalk.ip_repl |= ip_repl_mstr
    fedwalk.str_repl |= str_repl_mstr
    fedwalk.mac_repl |= mac_repl_mstr

def obf_on_submit(dirTree):    
    """
    Main function of the program, takes the list of files from the TLD and walks through them,\\
    performing a corresponding obfuscation based on the subdirectories they are located in
    
    Subdirectories: configs, syslogs, pcaps, fedwalk, rr
    """
    global debug_mode
    global agg_fedwalk

    save_fedwalk_for_last = []
    aggressive_fedwalk = []
    rr_ops = []

    for num, path in enumerate(dirTree):
        modified_fp = path.replace(og_workspace, mod_workspace, 1)

        if f"{sysslash}configs{sysslash}" in path:
            conf.mainLoop(opflags, path, modified_fp)
            if agg_fedwalk:
                aggressive_fedwalk.append(modified_fp)
            print(f"[CONFIG] - {path} obfuscated and written to {modified_fp}")
        elif f"{sysslash}syslogs{sysslash}" in path:
            log.mainloop(opflags, path, modified_fp)
            if agg_fedwalk:
                aggressive_fedwalk.append(modified_fp)
            print(f"[SYSLOG] - {path} obfuscated and written to {modified_fp}")
        elif f"{sysslash}pcaps{sysslash}" in path:
            pcap.mainloop(opflags, path, modified_fp)
            if agg_fedwalk:
                aggressive_fedwalk.append(modified_fp)
            print(f"[PCAP] - {path} obfuscated and written to {modified_fp}")
        elif f"{sysslash}fedwalk{sysslash}" in path:
            save_fedwalk_for_last.append((path, modified_fp))
            continue
        elif f"{sysslash}rr{sysslash}" in path:
            rr_ops.append((path, modified_fp))
            continue
        else:
            contents = ""
            with open(path, 'r') as exempt_file:
                contents = exempt_file.read()
            with open(modified_fp, 'w') as copy:
                copy.write(contents)
            print(f"[EXEMPT] - {path} exempted and copied to {modified_fp}")
            continue

        append_mstr_dicts()
        set_repl_dicts()

    clear_non_fedwalk_repl_dicts() # free up memory, all we're doing is fedwalk/regex replace now

    if len(save_fedwalk_for_last) > 0:
        start_time = time.time()
        sync_fedwalk_mstr_dicts()
        if num_procs < 1:
            for num, (src, dst) in enumerate(save_fedwalk_for_last):
                fedwalk.mainloop(opflags, src, dst)
                print(f"[FEDWALK] - {src} obfuscated and written to {dst}")
        else:
            srcs = []
            dsts = []
            for src, dst in save_fedwalk_for_last:
                srcs.append(src)
                dsts.append(dst)
            fedwalk.mainLoopMultiprocessed(opflags, srcs, dsts, num_procs)
        print(f"Execution took {time.time() - start_time} seconds")

    if agg_fedwalk and len(aggressive_fedwalk) > 0:
        sync_fedwalk_mstr_dicts()
        if num_procs < 1:
            for src in aggressive_fedwalk:
                fedwalk.mainloop(opflags, src, src)
                print(f"[FEDWALK] - Additional pass through on {src}, overwritten in place")
        else:
            fedwalk.mainLoopMultiprocessed(opflags, aggressive_fedwalk, aggressive_fedwalk, num_procs)
            print(f"[FEDWALK] - Additional pass through on {aggressive_fedwalk}, overwritten in place")

    sync_fedwalk_mstr_dicts()

    if len(rr_ops) > 0:
        for src, dst in rr_ops:
            try:
                REGEX_REPLACER = rr.RegexRep(src, dst, jsonFile=json_file, ordered=ordered_rr, generic_replace=generic_rep)
            except FileNotFoundError:
                print(f"[REGREPL] - {json_file} does not exist or the path is not correct,\
                      please provide the correct file or use the default /tools/precons.json file instead")
                logging.error(f"[REGREPL] - {json_file} does not exist or the path is not correct,\
                      please provide the correct file or use the default /tools/precons.json file instead")
            if import_rr:
                REGEX_REPLACER.loadRegex(import_rr)
            REGEX_REPLACER.openObfWrite()
            REGEX_REPLACER.writeRegex(jsonFile=json_file)
            print(f"[REGREPL] - {src} obfuscated and written to {dst}")
    
    map_output = ""

    map_output += "Master Dictionaries:\n\n>>> IP Addresses\n"
    for k,v in ip_repl_mstr.items():
        map_output += f"{k} -> {v}\n"
    map_output += "\n>>> MAC Addresses\n"
    for k,v in mac_repl_mstr.items():
        map_output += f"{k} -> {v}\n"
    map_output += "\n>>> Strings\n"
    for k,v in str_repl_mstr.items():
        map_output += f"{k} -> {v}\n"

    with open(f"mapof_{og_workspace}.txt", 'w') as mapfile_out:
        mapfile_out.write(map_output)

options = {"-pi, --preserve-ips":"Program scrambles routable IP(v4&6) addresses by default, use this option to preserve original IP addresses",\
           "-pm, --preserve-macs":"Disable MAC address scramble",\
           "-ps, --preserve-strings":"Disable sensitive string scramble",\
            "-sPIP, --scramble-priv-ips":"Scramble private/non-routable IP addresses",\
            "-sp, --scrub-payload":"Sanitize (some) payload in packet for pcaps",\
            "-ns":"Non-standard ports used. By default pcapsrb.py assumes standard port usage, use this option if the pcap to be scrubbed uses non-standard ports",\
            "-map=<MAPFILE>":"Take a map file output from any FFI program and input it into this program to utilize the same replacements",\
            "-agg":"Enables a second runthrough with fedwalk of all programs in these directories: 'configs', 'syslogs', and 'pcaps'",\
            "-d":"Enable debug logging",\
            "--override=<num_procs>":"Override the amount of child processes spawned for the 'fedwalk' runtime. Default is 4. Use at your own risk.\n",\
            "\nThe following options assume you are using the Regex Replacer (rr path) folder": "\n-----------------------------------------------------------------------------------\n",\
            "-ord":"Use if utilizing the 'rr' path. Makes it so order matters for regex replacement",\
            "-js=<JSON-FILE>": "Use a different JSON file to import regex strings and replacements. Look at .\\tools\\precons.json as an example",\
            "-gr": "Generic replacement, if you supply a regex statement and an empty replacement string, this flag will fill it with random characters",\
            "-ir=\"[regex,rep],[regex2,rep2],...\"": "set -ir equal to a list of lists containing regex and replacements \
(replacements can be empty). Ensure regex strings with backslash escapes are DOUBLE escaped (this is converted within the program)"}

if __name__ == "__main__":
    # Take in directory from the CLI
    args = sys.argv

    if len(args) < 2:
        print("Usage:\n\tpython fobf.py <directory> [options]")
        sys.exit()

    if args[1] == "-h":
        print("Options")
        for k,v in options.items():
            print(f"{k} : {v}")
        sys.exit()

    else:
        og_workspace = args[1]
        if len(args) > 2:
            for a in args[2:]:
                if '-map=' in a:
                    importMap(a.split('=')[1])
                elif '-d' in a:
                    debug_mode = True
                    log_lvl = logging.DEBUG
                elif '-ord' in a:
                    ordered_rr = True
                elif '-agg' in a:
                    agg_fedwalk = True
                elif '-gr' in a:
                    generic_rep = True
                elif '--override=' in a:
                    ui = input(f"You have specified the override setting. This will change the number \
of processes used to expedite obfuscation (Default = {num_procs}). Use this setting at your own risk.\n\
Do you wish to use {a.split('=')[1]} child processes?\n\t(y/N) > ")
                    
                    if 'y' in ui.lower():
                        try:
                            num_procs = int(a.split('=')[1])
                        except:
                            logging.warning("-mp needs to be passed an integer, skipping")
                elif '-ir=' in a:
                    rr_list = a.split('=')[1]
                    if rr_list:
                        try:
                            construct = []
                            subl = []
                            reg = ""
                            rep = ""
                            acom = False
                            close = False
                            for ch in rr_list:
                                if ',' in ch:
                                    if close:
                                        close = False
                                        continue
                                    acom = True
                                    subl.append(reg)
                                    continue
                                if ']' in ch:
                                    acom = False
                                    close = True
                                    subl.append(rep)
                                    construct.append(subl)
                                    continue
                                if '[' in ch:
                                    reg = ""
                                    rep = ""
                                    subl = []
                                    continue
                                if acom:
                                    rep += ch
                                    continue
                                reg += ch
                            for n, group in enumerate(construct):
                                import_rr[str(n)] = group

                        except:
                            print("-ir list is not formatted correctly:\n\t-ir=\"[reg1,rep1],[reg2,rep2]...\"\n")
                            x = input("Do you wish to continue?\n\t(y/N) > ")
                            if 'y' not in x:
                                sys.exit(0)
                elif '-js=' in a:
                    json_file = a.split('=')[1]
                else:
                    opflags.append(a)

        # Initialize logging with attrs
        logging.basicConfig(filename=log_fn, filemode='w', level=log_lvl, format=log_frmt)

    # Build target directory for modified files in the backend
    mod_workspace, dirtree_of_workspace = buildDirTree(og_workspace)
    files = getFiles(dirtree_of_workspace)

    obf_on_submit(files)