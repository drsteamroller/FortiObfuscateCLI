#!/usr/bin/env python3
# Author: Andrew McConnell
# Date: 03/15/2023

import re
import random
import time
import logging

t = int( time.time() * 1000.0 )
random.seed( ((t & 0xff000000) >> 24) +
             ((t & 0x00ff0000) >>  8) +
             ((t & 0x0000ff00) <<  8) +
             ((t & 0x000000ff) << 24))

# Global Variables
contents = []
og_filenames = 0
str_repl = dict()
ip_repl = dict()
opflags = []
mod_dir = ""

#REGEX ----> Use "group" function to select the part that matches https://docs.python.org/3/library/re.html#match-objects
ipaddr4 = r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
ipaddr6 = r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"

# Helper Functions
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

# a more granular check
def isValidIP6(addr):
    if type(addr) == bytes:
        addr = str(addr)[2:-1]
    
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

'''
How it works:
1) Split the IP into a list of 4 numbers (we assume IPv4)
  a) expect_0 is set to True when we view a shift in 1's to 0's                                V We set it to True so if there's a '1' after a '0', it's not a net_mask
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

    # Return true for quad 0 case so we don't replace 0.0.0.0 (default routes)
    if (ip_list == [0,0,0,0]):
        return True

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

# Replaces IP addresses
def replace_ip4(ip):
    if (isNetMask(ip)):
        return ip
    if (ip not in ip_repl.keys()):
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
    
    # If we've replaced it before, pick out that replacement and return it
    else:
        return ip_repl[ip]

def replace_ip6(ip):
    if not isValidIP6(ip):
         return ip

    if ip not in ip_repl.keys() and "-pi" not in opflags:
        repl = f'{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}'
        ip_repl[ip] = repl
        return repl
    elif ("-pi" not in opflags):
        return ip_repl[ip]
    else:
        return ip

def salt():
    return random.randint(2,8)

def replace_str(s):
    if s in str_repl.keys():
        return str_repl[s]

    repl = ""
    for ch in range(len(s) + salt()):
        c = 0
        if (random.random() > .5):
            c = chr(random.randint(65,90))
        else:
            c = chr(random.randint(97, 122))

        repl += c

    str_repl[s] = repl

    return repl

# Troubleshooting command to show the contents of what was loaded
def show():
    print(contents)

# Exports file that was loaded (pre or post obfuscation)
def export(modfile_name):
    modfilenames = [modfile_name]
    global debug_mes

    print(modfile_name)

    for index, w_file in enumerate(modfilenames):
        with open(w_file, 'w') as write:
            for line in contents[index]:
                write.write(line)
    
    logging.info(f"[CONF] Finished obfuscation, wrote modifications to {modfile_name}")

def showMap(op):
    if (not ip_repl):
        print("\nYou haven't obfuscated a configuration file yet\n")
        return

    ipv4s = "\t===>>> IPv4 ADDRESSES <<<===\nOriginal -> Replacement\n"
    ipv6s = "\t===>>> IPv6 ADDRESSES <<<===\nOriginal -> Replacement\n"
    
    for k, v in ip_repl.items():
        if len(v) > 15:
            ipv6s += f"{k} -> {v}\n"
        else:
            ipv4s += f"{k} -> {v}\n"
    sep = '=' * 50

    if (op == "p"):
        print(f"{ipv4s}\n{sep}\n{ipv6s}")
        return
    elif (op == "w"):
        with open(f"config_mapping.txt", 'w') as vi:
            vi.write("+---------- MAPPED IP ADDRESSES ----------+\n")
            for og, rep in ip_repl.items():
                vi.write(f"Original IP: {og}\nMapped IP: {rep}\n\n")
            vi.write("+---------- MAPPED MAC ADDRESSES ---------+\n\n")

            vi.write("+---------- MAPPED STRING VALUES ---------+\n")
            for og, rep in str_repl.items():
                vi.write(f"Original String: {og}\nMapped String: {rep}\n\n")
        print(f"\nMap file written to {og_filenames}_ipmapping.txt\n")
    else:
        print("\nUnknown option\n")

# Obfuscation main fuction
def obfuscate(conf):

    # If no file loaded, prompt to load a file
    if (not conf):
        return("\nEmpty\n")

    ## FOR LOOP EXT VARS ##
    # Compile the regex found at the top of this program
    is_ip4 = re.compile(ipaddr4)
    is_ip6 = re.compile(ipaddr6, re.MULTILINE)

    # Flags to look for "edit <name>" within snmp/vpn/VDOM config
    VDOM = False
    SNMP = False
    SNMP_HOSTS = False
    IPSEC_P1 = False
    IPSEC_P2 = False
    USER = False

    # Parse through the list containing the lines of the configuration file
    for j, content in enumerate(conf):

        leading = ""
        i = j+1 # Get the actual line number
        
        # Record the number of leading spaces, so we aren't having awkward lines that aren't in-line
        if (re.search('\S', content)):
            leading = " " * re.search('\S', content).start()
        
        # If we see certain values containing potentially sensitive strings, replace them
        if ("set hostname" in content or "set alias" in content or "description" in content or 'set vdom' in content):
            l = []
            name_o = ""
            name_r = ""
            try:
                l = content.strip().split(" ")
                if len(l) > 3:
                    l[2] = " ".join(l[2:])
                    l = l[0:3]
                if '"' in l[2]:
                    l[2] = l[2][1:-1]
                name_o = l[2].strip("\n")
                name_r = f"{replace_str(l[2])}"
                l[2] = f"{name_r}\n"
            except IndexError:
                logging.error(f"[CONF] \\ERROR\\ configuration file is not formatted correctly, index out of bounds\n\tMalformed line {i}: \"{content}\"")
            except Exception as e:
                logging.warning(f"[CONF] \\ERROR\\ something unexpected happened\n\tError {e}\n\tLine #{i}: \"{content}\"")
            else:
                logging.debug(f"[CONF] \\set hostname | alias | description\\ statement enountered and replaced at line #{i}\n\t{name_o}  ->  {name_r}")
                content = leading + "{} {} {}".format(l[0], l[1], l[2])            

        # If we see an IP address, check if it's public, and if so, replace it
        if (is_ip4.search(content)):
            ip_o = ""
            ip_r = ""
            try:
                a = is_ip4.search(content).span()
                g = content.strip().split(" ")
                if (len(g) == 3):
                    if ('"' in g[2]):
                        g[2] = g[2][1:-1]

                    ip_o = content[a[0]:a[1]]
                    ip_r = replace_ip4(content[a[0]:a[1]])
                    g[2] = ip_r
                    
                elif (len(g) > 3):
                    for b, ip in enumerate(g[2:]):
                        if is_ip4.search(ip):
                            ip_o = g[b + 2]
                            ip_r = g[b + 2] = replace_ip4(ip)
                
                elif (len(g) == 2):
                    a = is_ip4.search(g[1]).group()
                    g[1] = g[1].replace(a, replace_ip4(a))
                leading += " ".join(g)
            except IndexError:
                logging.error(f"[CONF] \\ERROR\\ configuration file is not formatted correctly, index out of bounds\n\tMalformed line {i}: \"{content}\"")
            except Exception as e:
                logging.warning(f"[CONF] \\ERROR\\ something unexpected happened\n\tError {e}\n\tLine #{i}: \"{content}\"")
            else:
                logging.debug(f"[CONF] \\IPv4 address REGEX encountered\\ statement enountered and replaced at line #{i}\n\t{ip_o}  ->  {ip_r}")
                content = leading + "\n"

        elif (is_ip6.search(content)):
            ip_o = ""
            ip_r = ""

            try:
                g = content.strip().split(" ")
                if (len(g) == 3):
                    if ('"' in g[2]):
                        g[2] = g[2][1:-1]
                    if ('/' in g[2]):
                        g[2] = replace_ip6(g[2].split('/')[0]) + g[2].split('/')[1]
                    else:
                        g[2] = replace_ip6(g[2])
                elif (len(g) > 3):
                    for b, ip in enumerate(g):
                        g[b + 2] = replace_ip6(ip)
                leading += " ".join(g)
            except IndexError:
                logging.error(f"[CONF] \\ERROR\\ configuration file is not formatted correctly, index out of bounds\n\tMalformed line {i}: \"{content}\"")
            except Exception as e:
                logging.warning(f"[CONF] \\ERROR\\ something unexpected happened\n\tError {e}\n\tLine #{i}: \"{content}\"")
            else:
                logging.debug(f"[CONF] \\IPv6 address REGEX encountered\\ statement enountered and replaced at line #{i}\n\t{ip_o}  ->  {ip_r}")
                content = leading + "\n"
        
        # special case catch
        elif 'set management-ip' in content:
            try:
                s = content.strip().split(" ")
                if len(s) > 3:
                    s[2] = " ".join(s[2:])
                    s = s[:3]
                if '"' in s[2]:
                    s[2] = s[2][1:-1]
                name = s[2]
                s[2] = replace_str(s[2])
                leading += " ".join(s)                
            except IndexError:
                logging.error(f"[CONF] \\ERROR\\ configuration file is not formatted correctly, index out of bounds\n\tMalformed line {i}: \"{content}\"")
            except Exception as e:
                logging.warning(f"[CONF] \\ERROR\\ something unexpected happened\n\tError {e}\n\tLine #{i}: \"{content}\"")
            else:
                logging.debug(f"[CONF] \\management-ip\\ statement enountered and replaced at line #{i}\n\t{name}  ->  {replace_str(s[2])}")
                content = leading + "\n"

        # General replacement
        if 'set comment' in content:
            content = leading + 'set comment ""\n'
            logging.debug(f"[CONF] \\set comment\\ statement encountered and erased at line #{i}\n")

        # Specific KEY-VALUE pair search:
        if "config vdom" in content:
            VDOM = True
            continue

        if VDOM and 'edit' in content:
            try:
                s = content.strip().split(" ")
                if len(s) > 2:
                    s[1] = " ".join(s[1:])
                    s = s[:2]
                if '"' in s[1]:
                    s[1] = s[1][1:-1]
                name = s[1]
                s[1] = replace_str(s[1])
                leading += " ".join(s)                
            except IndexError:
                logging.error(f"[CONF] \\ERROR\\ configuration file is not formatted correctly, index out of bounds\n\tMalformed line {i}: \"{content}\"")
            except Exception as e:
                logging.warning(f"[CONF] \\ERROR\\ something unexpected happened\n\tError {e}\n\tLine #{i}: \"{content}\"")
            else:
                logging.debug(f"[CONF] \\vdom > 'edit'\\ statement enountered and replaced at line #{i}\n\t{name}  ->  {replace_str(s[1])}")
                content = leading + "\n"

        if VDOM and 'end' in content:
            VDOM = False
            continue

        ### SNMP Communities ###
        if ("config system snmp community" in content or "config system snmp user" in content):
            SNMP = True
            continue
        
        if (not SNMP_HOSTS and SNMP and "edit" in content):
            s = []
            name = ""
            try:
                s = content.strip().split(" ")
                if (len(g) > 1):
                    name = s[1]
                    s[1] = f'{replace_str(name)}'
                
                leading += " ".join(s)
            except IndexError:
                logging.error(f"[CONF] \\ERROR\\ configuration file is not formatted correctly, index out of bounds\n\tMalformed line {i}: \"{content}\"")
            except Exception as e:
                logging.warning(f"[CONF] \\ERROR\\ something unexpected happened\n\tError {e}\n\tLine #{i}: \"{content}\"")
            else:
                logging.debug(f"[CONF] \\snmp | snmp_hosts > 'edit'\\ statement enountered and replaced at line #{i}\n\t{s[1]}  ->  {replace_str(name)}")
                content = leading + "\n"

        if (SNMP and "config hosts" in content):
            SNMP_HOSTS = True

        if (SNMP_HOSTS and "edit" in content):
            s = []
            name = ""
            try:
                s = content.strip().split(" ")
                if (len(g) > 1):
                    name = s[1]
                    s[1] = f'{replace_str(name)}'

                leading += " ".join(s)
            except IndexError:
                logging.error(f"[CONF] \\ERROR\\ configuration file is not formatted correctly, index out of bounds\n\tMalformed line {i}: \"{content}\"")
            except Exception as e:
                logging.warning(f"[CONF] \\ERROR\\ something unexpected happened\n\tError {e}\n\tLine #{i}: \"{content}\"")
            else:
                logging.debug(f"[CONF] \\SNMPv3 config hosts > 'edit'\\ statement enountered and replaced at line #{i}\n\t{s[1]}  ->  {replace_str(name)}")
                content = leading + "\n"

        if (SNMP and "name" in content):
            s = []
            name = ""
            try:
                s = content.strip().split(" ")
                name = s[2]
                leading += f'{s[0]} {s[1]} {replace_str(name)}\n'
            except IndexError:
                logging.error(f"[CONF] \\ERROR\\ configuration file is not formatted correctly, index out of bounds\n\tMalformed line {i}: \"{content}\"")
            except Exception as e:
                logging.warning(f"[CONF] \\ERROR\\ something unexpected happened\n\tError {e}\n\tLine #{i}: \"{content}\"")
            else:
                logging.debug(f"[CONF] \\SNMP edit name\\ statement enountered and replaced at line #{i}\n\t{s[2]}  ->  {replace_str(name)}")
                content = leading

        if (SNMP_HOSTS and "end" in content):
            SNMP_HOSTS = False
        
        if (not SNMP_HOSTS and SNMP and "end" in content):
            SNMP = False
        
        ### VPN Tunnel Names ###
        if ("config vpn ipsec phase1-interface" in content):
            IPSEC_P1 = True
            continue

        if ("config vpn ipsec phase2-interface" in content):
            IPSEC_P2 = True
            continue

        if (IPSEC_P1 and "set remotegw-ddns" in content):
            v = []
            repl = ""
            try:
                v = content.strip().split(" ")
                
                repl = f'{replace_str(v[2])}'
                
                leading += f'{v[0]} {v[1]} {repl}\n'
            except IndexError:
                logging.error(f"[CONF] \\ERROR\\ configuration file is not formatted correctly, index out of bounds\n\tMalformed line {i}: \"{content}\"")
            except Exception as e:
                logging.warning(f"[CONF] \\ERROR\\ something unexpected happened\n\tError {e}\n\tLine #{i}: \"{content}\"")
            else:
                logging.debug(f"[CONF] \\IPSEC P1 set remotegw-ddns\\ statement enountered and replaced at line #{i}\n\t{v[2]}  ->  {repl}")
                content = leading

        if (IPSEC_P1 and "edit" in content):
            v = []
            repl = ""
            try:
                v = content.strip().split(" ")
                repl = f'{replace_str(v[1])}'

                leading += f"{v[0]} {repl}\n"
            except IndexError:
                logging.error(f"[CONF] \\ERROR\\ configuration file is not formatted correctly, index out of bounds\n\tMalformed line {i}: \"{content}\"")
            except Exception as e:
                logging.warning(f"[CONF] \\ERROR\\ something unexpected happened\n\tError {e}\n\tLine #{i}: \"{content}\"")
            else:
                logging.debug(f"[CONF] \\IPSEC P1 edit\\ statement enountered and replaced at line #{i}\n\t{v[1]}  ->  {repl}")
                content = leading
            
        if (IPSEC_P2 and "edit" in content):
            v = []
            repl = ""
            try:
                v = content.strip().split(" ")
                repl = f'vpn_p2_{replace_str(v[1])}'

                leading += f"{v[0]} {repl}\n"
            except IndexError:
                logging.error(f"[CONF] \\ERROR\\ configuration file is not formatted correctly, index out of bounds\n\tMalformed line {i}: \"{content}\"")
            except Exception as e:
                logging.warning(f"[CONF] \\WARN\\ something unexpected happened\n\tError {e}\n\tLine #{i}: \"{content}\"")
            else:
                logging.debug(f"[CONF] \\IPSEC P2 edit\\ statement enountered and replaced at line #{i}\n\t{v[1]}  ->  {repl}")
                content = leading
        
        if (IPSEC_P2 and "set phase1name" in content):
            v = []
            repl = ""
            try:
                v = content.strip().split(" ")
                repl = replace_str(v[2])
                
                leading += f"{v[0]} {v[1]} {repl}\n"
            except IndexError:
                logging.error(f"[CONF] \\ERROR\\ configuration file is not formatted correctly, index out of bounds\n\tMalformed line {i}: \"{content}\"")
            except Exception as e:
                logging.warning(f"[CONF] \\WARN\\ something unexpected happened\n\tError {e}\n\tLine #{i}: \"{content}\"")
            else:
                logging.debug(f"[CONF] \\IPSEC P2 set phase1name\\ statement enountered and replaced at line #{i}\n\t{v[2]}  ->  {repl}")
                content = leading

        if (IPSEC_P1 and "end" in content):
            IPSEC_P1 = False
            continue

        if (IPSEC_P2 and "end" in content):
            IPSEC_P2 = False
            continue

        # Explicit 'config user ...' scrub
        if ("config user" in content):
            USER = True
            continue
        
        if USER and "edit" in content:
            comp = content.strip().split(" ")
            repl = ""
            try:
                repl = replace_str(comp[1])
                leading += f"{comp[0]} {repl}\n"
            except IndexError:
                logging.error(f"[CONF] \\ERROR\\ configuration file not formatted corretly, index out of bounds\n\tMalformed line {i}: \"{content}\"")
            except Exception as e:
                logging.warning(f"[CONF] \\WARN\\ Something unexpected happened\n\tError {e}\n\tLine #{i}: \"{content}\"")
            else:
                logging.debug(f"[CONF] \\USER edit\\ statement encountered and replaced at line #{i}\n\t{comp[1]}  ->  {repl}")
                content = leading

        if USER and ("dn" in content or "group-name" in content):
            # Special Distinguished Name scrub
            comp = content.strip().split(" ")
            repl = ""
            try:
                dn = comp[2]
                for h, el in enumerate(dn.split(",")):
                    eqsp = el.split("=")
                    repl += f"{eqsp[0]}={replace_str(eqsp[1])},"
                repl = repl[:-1]
                leading += f"{comp[0]} {comp[1]} {repl}\n"
            except IndexError:
                logging.error(f"[CONF] \\ERROR\\ configuration file not formatted corretly, index out of bounds\n\tMalformed line {i}: \"{content}\"")
            except Exception as e:
                logging.warning(f"[CONF] \\WARN\\ Something unexpected happened\n\tError {e}\n\tLine #{i}: \"{content}\"")
            else:
                logging.debug(f"[CONF] \\USER DN\\ statement encountered and replaced at line #{i}\n\t{comp[2]}  ->  {repl}")
                content = leading

        if USER and "username" in content:
            comp = content.strip().split(" ")
            repl = ""
            try:
                repl = replace_str(comp[2])
                leading += f"{comp[0]} {comp[1]} {repl}\n"
            except IndexError:
                logging.error(f"[CONF] \\ERROR\\ configuration file not formatted corretly, index out of bounds\n\tMalformed line {i}: \"{content}\"")
            except Exception as e:
                logging.warning(f"[CONF] \\WARN\\ Something unexpected happened\n\tError {e}\n\tLine #{i}: \"{content}\"")
            else:
                logging.debug(f"[CONF] \\USER username\\ statement encountered and replaced at line #{i}\n\t{comp[1]}  ->  {repl}")
                content = leading

        if USER and "end" in content:
            USER = False
            continue

        if "password" in content or "secret" in content or "passwd" in content:
            comp = content.strip().split(" ")
            leading += f"{comp[0]} {comp[1]}\n"
            logging.debug(f"[CONF] \\Password | Secret\\ statement encountered and removed at line #{i}")
            content = leading

        conf[j] = content

    return conf

def mainLoop(args: list, src_path: str, dst_path: str):

    contents.clear()
    global opflags
    opflags = args

    try:
        with open(src_path, 'r') as f:
            contents.append(f.readlines())
    except:
        debug_mes += f"[CONF] Could not find file {src_path}\n"

    obfuscated_contents = []

    for conf_file in contents:
        logging.info(f"[CONF] Entering obfuscation of {src_path}")
        obfuscated_contents.append(obfuscate(conf_file))
    
    export(dst_path)