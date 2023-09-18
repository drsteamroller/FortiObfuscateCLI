# regrepl.py - kinda like fedwalk.py but for power users
# Author - Andrew McConnell
# Date - 09/12/2023

import re
import json

class RegexRep:

    precons = {}
    srcfile = ""
    dstfile = ""
    contents = []

    def unescape(self, teststr):
        return teststr.replace("\\".encode('unicode-escape').decode(), chr(92))

    def reescape(self, teststr):
        return teststr.replace(chr(92), "\\".encode('unicode-escape').decode())

    def compile(self):
        for k, v in self.precons.items():
            self.precons[k] = [re.compile(v[0]), v[1]]

    def loadRegex(self, userSuppliedRegex={}):

        # expects {name:[regexstr, repstr]}, where repstr can be a blank string
        for k, v in userSuppliedRegex.items():
            if type(k) != str or type(v) != list:
                print("Program expects: dict{identifier:[regexstr, replacementstr]}, replacementstr can be an empty string for traditional replacement\n")
                return
            
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


    def openObfWrite(self):

        with open(self.srcfile, 'r') as sf:
            self.contents = sf.readlines()

        self.compile()

        for n, line in enumerate(self.contents):

            for k, [reg, rep] in self.precons.items():
                matches = reg.findall(line)
                if matches:
                    for match in matches:
                        try:
                            line = line.replace(match, rep)
                        except TypeError:
                            for el in match:
                                line = line.replace(el, rep)
                    self.contents[n] = line

        with open(self.dstfile, 'w') as df:
            df.writelines(self.contents)

    def __init__(self, src, dst, jsonFile="precons.json"):

        self.srcfile = src
        self.dstfile = dst

        with open(jsonFile, 'r') as JF:
            jsonl = json.load(JF)
            self.precons = jsonl['precons']

        for pk, pv in self.precons.items():
            self.precons[pk] = [self.unescape(pv[0]), pv[1]]

    def __str__(self):
        buildStr = ""

        buildStr += "\nPreconstructed Regex Entries\n"
        for pk, pv in self.precons.items():
            buildStr += f"\n{pk} : {pv}"

        return buildStr

def test():
    a = RegexRep()
    a.loadRegex({"test": ["someregex", "somereplacement"]})
    a.writeRegex()
    print(a)

# test()