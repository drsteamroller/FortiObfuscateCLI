# regrepl.py - kinda like fedwalk.py but for power users
# Author - Andrew McConnell
# Date - 09/12/2023

import re
import json
import time
import random

class RegexRep:

    ordered = False
    """
    Ordered vs Unordered regex: Some regex supplied could overlap with other regex supplied, in which
    case we would want to search for the most specific regex first, followed by the next specific, etc.

    Unordered is when all the regex strings provided do not overlap or depend on one another (Default option)
    """

    # precons = unordered regex dict
    precons = {}
    # ordered_regex = ordered regex list
    ordered_regex = []

    consistent_replace = {}

    # Source file to read from
    srcfile = ""
    # Destination file to write changes to
    dstfile = ""
    # Contents that are read in from srcfile
    contents = []
    generic_rep = False
    """
    Generic replace: If we specify generic_rep=True upon initialization, whenever we see an empty replacement string,
    instead of replacing the matched string with a blank '' string, we utilize the generic replacement function
    which replaces the matched string with a randomized string
    """        

    def unescape(self, teststr):
        """
        Replace '\\\\\\\\' from the read in regex strings to '\\\\'
        could come from the json file or user statements
        """
        return teststr.replace("\\".encode('unicode-escape').decode(), chr(92))

    def reescape(self, teststr):
        """
        Reverse of unescape, replaces '\\\\' with '\\\\\\\\' usually before writing to a json file
        """
        return teststr.replace(chr(92), "\\".encode('unicode-escape').decode())

    def compile(self):
        """
        Compile the regex strings loaded into precons or ordered_regex with imported re module
        """

        compiled_regrep = []

        if self.ordered:
            for i, [reg, rep] in enumerate(self.ordered_regex):
                compiled_regrep.append([re.compile(reg), rep])
        else:
            for i, [k, v] in enumerate(self.precons.items()):
                compiled_regrep.append([re.compile(v[0]), v[1]])
        
        return compiled_regrep

    def loadRegex(self, userSuppliedRegex={}):
        """
        Loads in regex&replacements post-initialization
        """
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
        """
        Write the regex out to jsonfile utilizing the json dump method
        """
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
        """
        Rudimentary salt which returns a number to add to the genericReplace method
        """
        return random.randint(2, 8)

    # For when the replacement is empty and we don't want to replace the match with an empty string
    def genericReplace(self, line, match):
        """
        This method takes the length of the match plus the returned salt value and generates a randomized string
        to be utilized as a replacement
        """
        if match in self.consistent_replace.keys():
            return self.consistent_replace[match]

        gen = ""
        for i in range(len(match) + self.salt()):
            gen += chr(random.randint(65, 90) + (32 * random.randint(0, 1)))

        self.consistent_replace[match] = gen
        return gen

    def openObfWrite(self):
        """
        Opens and reads open(self.srcfile)'s contents into self.contents\\
        Compiles loaded regex\\
        Parses through each line in self.contents and searches for regex matches\\
        If a match is found, replace it with the corresponding replacement string\\
        When finished, write the modifications to open(self.dstfile)
        """
        with open(self.srcfile, 'r') as sf:
            self.contents = sf.readlines()

        # To save ourselves from having to double the loop below, we can just reference the important parts
        # of unordered or ordered (precons or ordered_regex, resp.) regex data
        parsed = self.compile()

        for n, line in enumerate(self.contents):

            for i, [reg, rep] in enumerate(parsed):
                matches = reg.findall(line)
                if matches:
                    for match in matches:
                        try:
                            if len(rep)!=0 or not self.generic_rep:
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

    def __init__(self, src, dst, jsonFile="precons.json", ordered=False, generic_replace=False):
        """
        Initializes a RegexRep class with required variables:\\
        src = file to be read in\\
        dst = file for changes to be written to

        Optional variables:\\
        jsonFile = Specify a file to read in regex and replacement from\\
        ordered = True if certain regex statements read in will overlap or depend on an order to be replaced in
        """

        # Set the seed upon initialization
        t = int( time.time() * 1000.0 )
        random.seed( ((t & 0xff000000) >> 24) +
                ((t & 0x00ff0000) >>  8) +
                ((t & 0x0000ff00) <<  8) +
                ((t & 0x000000ff) << 24))

        self.srcfile = src
        self.dstfile = dst
        self.generic_rep = generic_replace

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
        """
        To string method to show the main parts of the class: ordered_regex or precons
        """
        buildStr = ""

        buildStr += f"\nPreconstructed {'ordered' if self.ordered else 'unordered'} Regex Entries\n"
        if self.ordered:
            for rr in self.ordered_regex:
                buildStr += f"\n{rr[0] : rr[1]}"
        else:
            for pk, pv in self.precons.items():
                buildStr += f"\n{pk} : {pv}"

        buildStr += "\nReplacement Mappings:\n"

        for m, g in self.consistent_replace.items():
            buildStr += f"{m} ---> {g}\n"


        return buildStr

def test():
    a = RegexRep(src="tstfile.txt")#, dst="tstfile_filtered.txt", generic_replace=True)
    a.loadRegex({"test": ["someregex", ""]})
    a.writeRegex()
    a.openObfWrite()
    print(a)

#test()