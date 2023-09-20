# regrepl.py - kinda like fedwalk.py but for power users
# Author - Andrew McConnell
# Date - 09/12/2023

import re
import json
import time
import random

class RegexRep:

    t = int( time.time() * 1000.0 )
    random.seed( ((t & 0xff000000) >> 24) +
             ((t & 0x00ff0000) >>  8) +
             ((t & 0x0000ff00) <<  8) +
             ((t & 0x000000ff) << 24))

    ordered = False
    precons = {}
    ordered_regex = []

    srcfile = ""
    dstfile = ""
    contents = []
    generic_rep = False

    def unescape(self, teststr):
        return teststr.replace("\\".encode('unicode-escape').decode(), chr(92))

    def reescape(self, teststr):
        return teststr.replace(chr(92), "\\".encode('unicode-escape').decode())

    def compile(self):
        if self.ordered:
            for i, [reg, rep] in enumerate(self.ordered_regex):
                self.ordered_regex[i] = [re.compile(reg), rep]
        else:
            for k, v in self.precons.items():
                self.precons[k] = [re.compile(v[0]), v[1]]

    def loadRegex(self, userSuppliedRegex={}):

        # expects {name:[regexstr, repstr]}, where repstr can be a blank string
        for k, v in userSuppliedRegex.items():
            if type(k) != str or type(v) != list:
                print("Program expects: dict{identifier:[regexstr, replacementstr]},\
                       replacementstr can be an empty string for traditional replacement\n")
                return
            if self.ordered:
                self.ordered_regex.append(v)
            else:
                self.precons[k] = [self.unescape(v[0]), v[1]]
            
    def writeRegex(self, jsonFile="precons.json"):
        
        existingJSON = {}
        try:
            with open(jsonFile, 'r') as JF:
                existingJSON = json.load(JF)
                existingJSON['precons'] = self.precons
        except:
            print("No existing JSON file (read + write files are different)\n")

        with open(jsonFile, 'w') as JF:
            if existingJSON:
                json.dump(existingJSON, JF, indent=4)
            else:
                json.dump({"precons": self.precons}, JF, indent=4)

    def salt(self):
        return random.randint(2, 8)

    # If the replacement is empty and we want to generic replace, do it
    def genericReplace(self, line, match):
        gen = ""
        for i in range(len(match) + self.salt()):
            gen += chr(random.randint(65, 90) + (32 * random.randint(0, 1)))

        return gen

    def openObfWrite(self):

        with open(self.srcfile, 'r') as sf:
            self.contents = sf.readlines()

        self.compile()

        # To save ourselves from having to double the loop below, we can just reference the important parts
        # of unordered or ordered (precons or ordered_regex, resp.) regex data
        parsed = []
        if self.ordered:
            parsed = self.ordered_regex
        else:
            parsed = self.precons.values()

        for n, line in enumerate(self.contents):

            for i, [reg, rep] in enumerate(parsed):
                matches = reg.findall(line)
                if matches:
                    for match in matches:
                        try:
                            if rep or not self.generic_rep:
                                line = line.replace(match, rep)
                            else:
                                gr = self.genericReplace(line, match)
                                line = line.replace(match, gr)
                                parsed[i][1] = gr

                        except TypeError:
                            print(match)

                            # replacement test line
                            test_rep_line = line
                            common_delimiters = '.,_*|\\/'

                            for deli in common_delimiters:
                                test_rep_line = line.replace(deli.join(match), rep)

                                # If we replaced something, break out of loop
                                if test_rep_line not in line:
                                    break

                            for el in match:
                                line = line.replace(el, rep)
                    self.contents[n] = line

        with open(self.dstfile, 'w') as df:
            df.writelines(self.contents)

    def __init__(self, src, dst, jsonFile="precons.json", ordered=False):
        """
        Initializes a RegexRep class with required variables:\\
        src = file to be read in\\
        dst = file for changes to be written to

        Optional variables:\\
        jsonFile = Specify a file to read in regex and replacement from\\
        ordered = True if certain regex statements read in will overlap or depend on an order to be replaced in
        """
        self.srcfile = src
        self.dstfile = dst

        jsonl = {}
        with open(jsonFile, 'r') as JF:
            jsonl = json.load(JF)

        if ordered:
            self.ordered = True
            for v in jsonl['precons'].values():
                self.ordered_regex.append(v)
        else:        
            self.precons = jsonl['precons']

            for pk, pv in self.precons.items():
                self.precons[pk] = [self.unescape(pv[0]), pv[1]]

    def __str__(self):
        buildStr = ""

        buildStr += f"\nPreconstructed {'ordered' if self.ordered else 'unordered'} Regex Entries\n"
        if self.ordered:
            for rr in self.ordered_regex:
                buildStr += f"\n{rr[0] : rr[1]}"
        else:
            for pk, pv in self.precons.items():
                buildStr += f"\n{pk} : {pv}"

        return buildStr

def test():
    a = RegexRep()
    a.loadRegex({"test": ["someregex", "somereplacement"]})
    a.writeRegex()
    print(a)

# test()