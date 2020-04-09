#!/usr/bin/env python

#import pyperclip
import os
import sys
import parser
from shutil import copyfile
import subprocess

#import nmap
import re

#import simplepayloadlib

nmapscans = {}
services = {}

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
        # print 'Changing "{old_string}" to "{new_string}" in {filename}'.format(**locals())
        s = s.replace(old_string, new_string)
        f.write(s)
        f.close()
        return


# append to file, text
def add_to_port_report(path, port,service,version,banner=""):

    filepath = file(path, "a")
    filepath.write("------------------------------------\n")

    port = "Open Port: %s \n" % (port)
    service = "Service: %s \n" % service
    version = "Version: %s \n" % (version)
    banner = "Banner: %s \n" % (banner)

    filepath.write(port)
    filepath.write(service)
    filepath.write(version)
    filepath.write(banner)

    filepath.write("------------------------------------\n")
    filepath.close()


# returns a list of open ports
def nmap_open_ports(nlog):

    #print "NLOG PATH: " + nlog

    #openports_regx = "^^(\\d{1,5})\\.(tcp|udp).*$"
    openports_regx = "(\\d{1,5})\\/(tcp|udp)"
    #openports_regx = "\s+/(open)"

    f = open(nlog,"r")
    p = f.readlines()

    ports = set(re.findall(openports_regx,str(p)))

    #print "FOUND PORTS"

    #for p in ports:

    #   print "PORT: " + str(p)

    return ports



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

def load_nmap_scans():
    f = open("/root/PycharmProjects/ProjectBuilder/vulns_commands.txt","r")
    lines = f.read()

    #print lines

    for l in lines.splitlines():
        #print l
        port,scan = l.split(":")


        #print splitscan[1]

        nmapscans[port] = scan

    print "Loaded %s, nmap scan commands" % (len(nmapscans))
    return

def port_info(port):

    p = "Port: %s\n" %(port)

    v = "Version:\n"

    if port in nmapscans:
        scan =  nmapscans[port]
        nmscan = str(scan).replace("[ipAddress]",folder)


    return p+v+nmscan+"\n\nOPEN_PORT\n"


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

def initialscan(host):

    try:
        scanlogpath = os.getcwd() + "/nmap-scans"
        #print scans
        nm = "nmap -Pn -n -sV -p- -T4 -oA %s/initial-%s %s" % (scanlogpath,host,host)
        print(nm)
        subprocess.check_call(nm, shell=True)



    except:
        print "Error"

def replace_string(text,old,new):


    n = str(text).replace(old,new)

    return n



def scan_host_udp(host):

    print "UDP Scanning: " + str(host)

    openport = ""

    scanlogpath = os.getcwd() + "/nmap-scans"
    #print scans
    nmscan = "-Pn -T4 -sU -oN %s/initial-udp-%s " % (scanlogpath,host)
    nm = nmap.PortScanner()

    nm.scan(host,"53,69,113,135,137,161,500,1026,1434,4500", arguments=nmscan)
    nm.command_line()


    print nm[host].hostname()

    for host in nm.all_hosts():

       # print('----------------------------------------------------')
        #print('Host : %s (%s)' % (host, nm[host].hostname()))
        #print('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
         #   print('----------')
          #  print('Protocol : %s' % proto)

            lport = nm[host][proto].keys()
            lport.sort()
            for port in lport:

                # print help(nm)
                #host;protocol;port;name;state;product;extrainfo;reason;version;conf

                #if not nm[host][proto][port]["state"] == "open|filtered" or "closed":
                if not nm[host][proto][port]["state"] in ["open|filtered","closed"]:

                    port_results = ("""port : %s
                State : %s
                Service : %s
                Product : %s
                Version : %s\n""") % (port,
                                            nm[host][proto][port]["state"],
                                            nm[host][proto][port]['name'],
                                            nm[host][proto][port]['product'],
                                            nm[host][proto][port]['version'])
                    openport += port_results
                    #print nmapscans.keys()

                    if str(port) in nmapscans:

                        g = nmapscans[str(port)]
                        openport += g

                        openport = openport.replace("[ipAddress]", str(host))
                        openport = openport.replace("[port]", str(port))


                if not nm[host][proto][port]['product'] == "" or not nm[host][proto][port]['version'] =="":
                    r = nm[host][proto][port]['product'] + " " + nm[host][proto][port]['version']
                    services[str(port)] = r

                else:
                    pass
                    #openport += "manual probe PORT " + str(port)
                    #if port in nmapscans:
                    #   openport += nmapscans[port]
    #print openport
    return openport

def scan_host_tcp(host):
    print "TCP Scanning: " + str(host)

    openport = ""

    scanlogpath = os.getcwd() + "/nmap-scans"
    #print scans
    nmscan = "-Pn -n -sV -T4 -oN %s/initial-tcp-%s %s" % (scanlogpath,host,host)
    nm = nmap.PortScanner()


    nm.scan(host,"-",arguments=nmscan)
    print nm.command_line()
    print nm.get_nmap_last_output()

    f = open("./nmap-scans/scan.xml","w")
    f.write(nm.get_nmap_last_output())
    f.close()

    print nm[host].hostname()

    for host in nm.all_hosts():

        #print('----------------------------------------------------')
        #print('Host : %s (%s)' % (host, nm[host].hostname()))
        #print('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
         #   print('----------')
          #  print('Protocol : %s' % proto)

            lport = nm[host][proto].keys()
            lport.sort()
            for port in lport:

                # print help(nm)
                #host;protocol;port;name;state;product;extrainfo;reason;version;conf
                port_results = ("""
                port : %s
                    State : %s
                    Service : %s
                    Product : %s
                    Version : %s\n""") % (port,
                                        nm[host][proto][port]["state"],
                                        nm[host][proto][port]['name'],
                                        nm[host][proto][port]['product'],
                                        nm[host][proto][port]['version'])
                openport += port_results

                if not nm[host][proto][port]['product'] == "" or not nm[host][proto][port]['version'] =="":
                    r = nm[host][proto][port]['product'] +" " + nm[host][proto][port]['version']
                    services[str(port)] = r


                if nm[host][proto][port]['name'] == "ssh":
                    g = nmapscans["22"]
                    openport += g

                    openport = openport.replace("[ipAddress]", str(host))
                    openport = openport.replace("[port]", str(port))


                elif nm[host][proto][port]['name'] == "ftp":
                    g = nmapscans["21"]
                    openport += g

                    openport = openport.replace("[ipAddress]", str(host))
                    openport = openport.replace("[port]", str(port))

                elif nm[host][proto][port]['name'] == "mysql":
                    g = nmapscans["3306"]
                    openport += g

                    openport = openport.replace("[ipAddress]", str(host))
                    openport = openport.replace("[port]", str(port))

                elif nm[host][proto][port]['name'] == "pop3":
                    g = nmapscans["110"]
                    openport += g

                    openport = openport.replace("[ipAddress]", str(host))
                    openport = openport.replace("[port]", str(port))

                elif nm[host][proto][port]['name'] == "smtp":
                    g = nmapscans["25"]
                    openport += g

                    openport = openport.replace("[ipAddress]", str(host))
                    openport = openport.replace("[port]", str(port))

                elif nm[host][proto][port]['name'] == "http":
                    f = open("../http-probe","r")
                    g = f.read()
                    openport += g
                    #g = nmapscans["80"]
                    #openport += g

                    openport = openport.replace("[ipAddress]", str(host))
                    openport = openport.replace("[port]", str(port))

                elif nm[host][proto][port]['name'] == "netbios-ssn":
                    f = open("../smb-probe", "r")
                    g = f.read()
                    openport += g
                    g = nmapscans["139"]
                    openport += g

                    openport = openport.replace("[ipAddress]", str(host))
                    openport = openport.replace("[port]", str(port))

                elif nm[host][proto][port]['name'] == "microsoft-ds":
                    f = open("../smb-probe", "r")
                    g = f.read()
                    openport += g
                    g = nmapscans["445"]
                    openport += g

                    openport = openport.replace("[ipAddress]", str(host))
                    openport = openport.replace("[port]", str(port))

                elif nm[host][proto][port]['product'] == "" or nm[host][proto][port]['name'] == "":
                    openport += "manual probe PORT \n"
                    openport += "nc [targetIp] [port]\n"
                    openport += "telnet [targetIp] [port]\n"
                    openport += "amap -d [targetIp] [port]\n"

                    openport = openport.replace("[ipAddress]", str(host))
                    openport = openport.replace("[port]", str(port))


                elif nm[host][proto][port]['name'] == "unknown":
                    openport += "nc [ipAddress] [port]\n"
                    openport += "telnet [ipAddress] [port]\n"
                    openport += "amap -d [targetIp] [port]\n"

                    openport = openport.replace("[ipAddress]", str(host))
                    openport = openport.replace("[port]", str(port))

                elif str(port) in nmapscans:
                        g = nmapscans[str(port)]
                        openport += g

                        openport = openport.replace("[ipAddress]", str(host))
                        openport = openport.replace("[port]", str(port))

                else:
                    pass
                    #openport += "manual probe PORT " + str(port)
                    #if port in nmapscans:
                    #   openport += nmapscans[port]
            #openport = replace_string(openport,"[ipAddress]",host)

    #print openport

    return openport



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

            #print "New Project Folder Created: " + folder
            #print "Running inital scan on %s" % (folder)
            #load_nmap_scans()

            #print nmapscans.keys()
            #initialscan(folder)
            #port_data_tcp = scan_host_tcp(folder)
            #port_data_udp = scan_host_udp(folder)



            #print folder
            #results = port_data_udp
            #results = port_data_tcp + port_data_udp


            #print "RESULTS"
            #print "==========================="
            #print results
            #print ""

            #print "Result copied to clipboard"
            #pyperclip.copy(results)

            #f = "./nmap-scans/initial-%s.nmap" %(folder)
            #open_ports = nmap_open_ports(f)

            #l = "./linux-auditscript.md"
            #w = "./windows-auditscript.md"

            #inplace_change(l,"OPEN_PORTS",results)
            #inplace_change(w,"OPEN_PORTS",results)

            #print "Searchsploit services"
            #print "======================="
            #for k in services.keys():
                #print "[%s] searchsploit %s" %(k,services[k])


    except Exception as e:
        print "ERROR: "
        print e



if __name__ == '__main__':
    main()
