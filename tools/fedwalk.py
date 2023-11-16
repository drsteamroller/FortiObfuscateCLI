#! /usr/bin/env python3
# Description: 'Walk' through a directory and replace specified strings/IP addresses (FMG/FAZ backups are full directories containing DB backups)
# Author: Andrew McConnell
# Date:   5/4/2023

import re
import random
import logging
from binaryornot.check import is_binary
import multiprocessing as mp

# GLOBAL VARS

opflags = []
depth = 0

str_repl = dict()
ip_repl = dict()
mac_repl = dict()

ip4 = re.compile(r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
#ip4_bin = re.compile(b'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
ip6 = re.compile(r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))")
#ip6_bin = re.compile(b"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))")


# Helper Functions

# RFC1918 Detector
def isRFC1918(ip):
    a,b,c,d = ip.split('.')

    # Very explicitly checks if the addresses are RFC 1918 Class A/B/C addresses
    if (int(a) == 10):
        return(True)
    elif(int(a) == 172 and int(b) in range(16,32)):
        return(True)
    elif(int(a) == 192 and int(b) == 168):
        return(True)
    else:
        return(False)

# Check if valid IPv6 address
def isValidIP6(addr):
    if type(addr) == bytes:
        addr = str(addr)[2:-1]
    
    if len(addr) < 3:
        return False

    if " " in addr:
        return False
    
    maxcol = 7
    mincol = 2
    countcol = 0
    maxnums = 4
    countnums = 0
    validchars = re.compile(r'[A-Fa-f0-9:]')

    for num in addr:
        ch = validchars.search(num)
        if not ch:
            return False
        
        if num in ':':
            countcol += 1
            if countnums > maxnums:
                return False
            countnums = 0
        else:
            countnums += 1

    if countcol < mincol or countcol > maxcol:
        return False

    return True

# Subnet mask detector (Insert if needed)
'''
How it works:
1) Split the IP into a list of 4 numbers (we assume IPv4)
  a) expect_0 is set to True when we view a shift in 1's to 0's                             V We set it to True so if there's a '1' after a '0', it's not a net_mask
                                                    ===> 255.255.240.0 = 11111111.11111111.11110000.00000000
  b) constant is a catch-all for when we detect it isn't (or is!!!) a net_mask, and we return it accordingly

2) We take each value in the ip_list and check if it's non zero
  a) If it's non zero, we subtract 2^i from that value where i is a list from 7 to 0 (decremented).
    i) If the value hits zero during this process and i is not zero, set expect_0 to True and break out of the process [val is zero so we don't need to subtract any more]
    ii) If the value hits zero during the process and i IS zero (255 case), we continue to the next value
    ###### IF AT ALL DURING THIS PROCESS THE VALUE GOES BELOW ZERO, WE SET constant = False AND BREAK AND 'return constant' ######
  b) If the value starts out as zero, we don't bother with the process and just set expect_0 to True (catches 255.0.255.0 and similar cases)
'''
def isNetMask(ip):
    _ = ip.split('.')
    ip_list = list()
    for item in _:
        ip_list.append(int(item))

    # Return false for quad 0 case (default routes)
    if (ip_list == [0,0,0,0]):
        return False

    # Netmasks ALWAYS start with 1's
    expect_0 = False
    # We start out assuming constancy
    constant = True

    for val in ip_list:
        if (val != 0):
            for i in range(7, -1, -1):
                val = val - pow(2, i)
                if (val > 0 and not expect_0):
                    continue
                elif (val == 0  and i != 0):
                    expect_0 = True
                    break
                elif (val == 0 and not expect_0 and i == 0):
                    break
                else:
                    constant = False
                    break
            if (not constant):
                break
        else:
            expect_0 = True
    return constant

# Mask IPs
# TODO: Implement a delimeter search as well (replace periods with dashes, underscores, spaces, etc)
def replace_ip4(ip):
    if (isNetMask(ip)):
        return ip
    if ('0.0.0.0' == ip):
        return ip
    # If we've replaced it before, pick out that replacement and return it
    try:
        return ip_repl[ip]
    except:
        repl = ""
        if (isRFC1918(ip) and "-sPIP" in opflags and "-pi" not in opflags):
            octets = ip.split('.')
            repl = f"{octets[0]}.{octets[1]}.{random.randrange(0, 256)}.{random.randrange(1, 256)}"
        elif (not isRFC1918(ip) and "-pi" not in opflags):
            repl = f"{random.randrange(1, 255)}.{random.randrange(0, 255)}.{random.randrange(0, 255)}.{random.randrange(1, 255)}"
        else:
            repl = ip
        ip_repl[ip] = repl
        return repl

def replace_ip6(ip):

    if not isValidIP6(ip):
        return ip
    
    if (ip not in ip_repl.keys() and "-pi" not in opflags):
        repl = f'{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}'
        ip_repl[ip] = repl
        return repl
    elif ("-pi" not in opflags):
        return ip_repl[ip]
    else:
        return ip

def replace_str(s):
    if s in str_repl.keys():
        return str_repl[s]

    return s

# MP Functions:
def replace_ip4MP(ip, mgr, ag):

    if (isNetMask(ip)):
        return ip
    if ('0.0.0.0' == ip):
        return ip
    
    # If we've replaced it before, pick out that replacement and return it
    try:
        return mgr[ip]

    except:
        repl = ""
        if (isRFC1918(ip) and "-sPIP" in ag and "-pi" not in ag):
            octets = ip.split('.')
            repl = f"{octets[0]}.{octets[1]}.{random.randrange(0, 256)}.{random.randrange(1, 256)}"
        elif (not isRFC1918(ip) and "-pi" not in ag):
            repl = f"{random.randrange(1, 255)}.{random.randrange(0, 255)}.{random.randrange(0, 255)}.{random.randrange(1, 255)}"
        else:
            repl = ip
        mgr[ip] = repl
        return repl

def replace_ip6MP(ip, mgr, ag):
    if not isValidIP6(ip):
        return ip
    
    if (ip not in mgr.keys() and "-pi" not in ag):
        repl = f'{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}'
        mgr[ip] = repl
        return repl
    elif ("-pi" not in ag):
        return mgr[ip]
    else:
        return ip

def replace_strMP(str, mgr):
    try:
        return mgr[str]
    except:
        return str

mtd = ""

def modifyTxtFile(txtfile):
    if type(txtfile) != list:
        return txtfile

    for i, line in enumerate(txtfile):
        
        ipsearch = ip4.findall(line)
        
        if ipsearch:
            # Doctor the findings so it's easier to replace
            ph = []
            for z in ipsearch:
                ph.append(f"{z[0]}.{z[1]}.{z[2]}.{z[3]}")
            ipsearch = ph

            # actually replace
            for ip in ipsearch:
                line = line.replace(ip, replace_ip4(ip))
                logging.debug(f"[FEDWALK_txt] \\ipv4 address\\ identified and replaced:\n\t{ip} -> {replace_ip4(ip)}")

        ip6search = ip6.findall(line)
        
        if ip6search:
            ph = []
            for z in ip6search:
                s = [f"{p}" for p in z]
                ph.append(s[0])
            ip6search = ph

            for i6 in ip6search:
                line = line.replace(i6, replace_ip6(i6))
                logging.debug(f"[FEDWALK_txt] \\ipv6 address\\ identified and replaced:\n\t{i6} -> {replace_ip6(i6)}")

        for k, v in str_repl.items():
            strsearch = re.findall(k, line)
            if strsearch:
                for ss in strsearch:
                    line = line.replace(ss, replace_str(ss))
                    logging.debug(f"[FEDWALK_txt] \\string\\ identified and replaced:\n\t{ss} -> {replace_str(ss)}")
        
        txtfile[i] = line

    return txtfile

'''
def modifyBinFile(binfile):
    if type(binfile) != list:
        return binfile

    for i, line in enumerate(binfile):
        
        bipsearch = ip4_bin.findall(line)
        
        reconstruct = []
        for boct in bipsearch:
            bip = bytes(f"{str(boct[0])[2:-1]}.{str(boct[1])[2:-1]}.{str(boct[2])[2:-1]}.{str(boct[3])[2:-1]}", encoding="utf-8")
            reconstruct.append(bip)

        bipsearch = reconstruct
        for bip in bipsearch:
            strrep = str(bip)[2:-1]
            repl = bytes(replace_ip4(strrep), 'utf-8')
            line = line.replace(bip, repl)
            logging.debug(f"[FEDWALK_bin] \\ipv4 address\\ identified and replaced:\n\t{bip[2:-1]} -> {repl[2:-1]}")
        
        binfile[i] = line

    return binfile
'''
def mpmodifyTxtFile(args):
    txtfile, ip_mgr, str_mgr, procnum, ag, ip_repld, str_repld = args

    ip_cache = ip_repld
    str_cache = str_repld

    log = []

    if type(txtfile) != list:
        return txtfile
    
    try:
        for i, line in enumerate(txtfile):
            
            ipsearch = ip4.findall(line)
            
            if ipsearch:
                # Doctor the findings so it's easier to replace
                ph = []
                for z in ipsearch:
                    ph.append(f"{z[0]}.{z[1]}.{z[2]}.{z[3]}")
                ipsearch = ph

                # actually replace
                for ip in ipsearch:
                    repl = ""
                    try:
                        line = line.replace(ip, ip_cache.get())
                    except:
                        repl = replace_ip4MP(ip, ip_mgr, ag)
                        line = line.replace(ip, repl)
                        ip_cache[ip] = repl
                    log.append(f"[FEDWALK_txt] \\ipv4 address\\ identified and replaced:\n\t{ip} -> {repl}")


            ip6search = ip6.findall(line)
            
            if ip6search:
                ph = []
                for z in ip6search:
                    s = [f"{p}" for p in z]
                    ph.append(s[0])
                ip6search = ph

                for i6 in ip6search:
                    repl = ""
                    try:
                        line = line.replace(i6, ip_cache[i6])
                    except:
                        repl = replace_ip4MP(i6, ip_mgr)
                        line = line.replace(i6, repl, ag)
                        ip_cache[i6] = repl
                    log.append(f"[FEDWALK_txt] \\ipv6 address\\ identified and replaced:\n\t{i6} -> {repl}")


            for k, v in str_repl.items():
                strsearch = re.findall(k, line)
                if strsearch:
                    for ss in strsearch:
                        try:
                            line = line.replace(ss, str_cache[ss])
                        except:
                            repl = replace_strMP(ss, str_mgr)
                            line = line.replace(ss, repl)
                            str_cache[ss] = repl
                    log.append(f"[FEDWALK_txt] \\string\\ identified and replaced:\n\t{ss} -> {repl}")

            
            txtfile[i] = line
    except Exception as e:
        print(f"Process {procnum} encountered {e}")

    return [txtfile, log]

# Alternate main function with multiprocessing
def mainLoopMultiprocessed(args: list, src_paths: list, dst_paths: list, num_cpus):

    global ip_repl
    global str_repl
    global opflags
    
    opflags = args
    
    # read all the src files into fileLines, record their sizes in order in fileSizes
    fileLines = []
    fileSizes = []

    # Grab total size in lines
    totalSize = 0
    
    for src in src_paths:
        with open(src, 'r') as f:
            lines = f.readlines()
            fileLines.extend(lines)
            fileSizes.append(len(lines))
    
    totalSize = sum(fileSizes)
    
    chunkSize = round(totalSize/num_cpus)
    
    segments = []

    for i in range(num_cpus-1):
        segments.append(fileLines[i*chunkSize:(i+1)*chunkSize])

    segments.append(fileLines[chunkSize*(num_cpus-1):])

    proc_logs = []

    shared_resource_mgr = mp.Manager()

    return_dict = {}
    ip_mgr = shared_resource_mgr.dict(ip_repl)
    str_mgr = shared_resource_mgr.dict(str_repl)

    ## MP Stuff
    with mp.Pool(processes=num_cpus) as pool:
        pool_results = pool.map(mpmodifyTxtFile, [(seg, ip_mgr, str_mgr, e, opflags, ip_repl.copy(), str_repl.copy()) for e, seg in enumerate(segments)])
        pool.close()
        pool.join()

        for e, result in enumerate(pool_results):
            return_dict[e] = result[0]
            proc_logs.extend(result[1])

    '''procList = []
    for e, seg in enumerate(segments):
        p = mp.Process(target=mpmodifyTxtFile, args=(seg, ip_mgr, str_mgr, e, return_dict))
        procList.append(p)
        p.start()

    print("All processes started, waiting for them to complete: ")
    for p in procList:
        p.join()
    print("All processes complete")'''
    ## End MP Stuff

    ip_repl = ip_mgr.copy()
    str_repl = str_mgr.copy()

    fileLines = []
    for e, val in enumerate(return_dict.values()):
        fileLines.extend(return_dict[e])

    offset = 0
    for e, size in enumerate(fileSizes):
        with open(dst_paths[e], 'w') as wr:
            wr.writelines(fileLines[offset:offset+size])
            offset += size
    
    for logline in proc_logs:
        logging.debug(logline)

def mainloop(args: list, src_path: str, dst_path: str):

    global opflags
    opflags = args

    contents = None
    r_mode = ''
    w_mode = ''

    if is_binary(src_path):
        r_mode = 'rb'
        w_mode = 'wb'
    else:
        r_mode = 'r'
        w_mode = 'w'

    with open(src_path, r_mode) as rf:
        contents = rf.readlines()

    if r_mode == 'rb':
        #contents = modifyBinFile(contents)
        pass
    
    contents = modifyTxtFile(contents)
    
    with open(dst_path, w_mode) as wf:
        wf.writelines(contents)

if __name__ == '__main__':
    pass