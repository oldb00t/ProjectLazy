#!/usr/bin/env python

#import pyperclip
import os
import sys
import parser
from shutil import copyfile
import subprocess
import re

def inplace_change(filename, old_string, new_string):
    # Safely read the input filename using 'with'
    with open(filename) as f:
        s = f.read()
        if old_string not in s:
            print '"{old_string}" not found in {filename}.'.format(**locals())
            f.close()
            return

    # Safely write the changed content, if found in the file
    with open(filename, 'w') as f:
        #print 'Changing "{old_string}" to "{new_string}" in {filename}'.format(**locals())
        s = s.replace(old_string, new_string)
        f.write(s)
        f.close()
        return




def usage():
    print "usage()"
    print ""
    print "Project Builder"
    print ""
    print "projectbuild 10.10.10.10"
    print ""


if len(sys.argv) != 2:
    usage()
    sys.exit(1)

folder = sys.argv[1]


def main():

    try:
        if os.path.exists(folder):
            print "Project folder exists %s" % folder
            sys.exit(1)
        else:
            os.makedirs(folder)
            os.makedirs(folder + "/nmap-scans")
            os.makedirs(folder + "/web")
            os.makedirs(folder + "/exploits")
            os.symlink('/root/Tools', folder + '/Tools')
            os.symlink('/usr/share/wordlists', folder + '/wordlists')
            copyfile("linux-mapping.md", folder + '/linux-auditscript.md')
            copyfile("windows-mapping.md", folder + '/windows-auditscript.md')
            copyfile("init-scan.sh", folder + '/quick-scan.sh')
            inplace_change(folder + "/linux-auditscript.md","INSERTIPADDRESS",folder)
            inplace_change(folder + "/windows-auditscript.md","INSERTIPADDRESS",folder)
            inplace_change(folder + "/quick-scan.sh","INSERTIPADDRESS",folder)
            os.chdir(folder)
         

    except Exception as e:
        print "ERROR: "
        print e



if __name__ == '__main__':
    main()
