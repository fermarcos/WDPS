#!/usr/bin/python
#####################################################################
# Python script to set up an iptables policy. For Debian, Ubuntu and CentOS systems.
# Written by Fernando Marcos Parra Arroyo
# ###################################################################
import re
import sys
import os
import itertools
import commands
import ConfigParser
from optparse import OptionParser
#Funcion para cargar la configuracion
def loadConfig(configFile):
    global webPorts, sshPorts, mysqlPorts, psqlPorts
    global webAllowedIP, sshAllowedIP, mysqlAllowedIP, psqlAllowedIP
    global webDirectory, serverIP
    #Cargando configuraciones
    config = ConfigParser.ConfigParser()
    config.read(configFile)

    serverIP = config.get("Server","ip")
    #SiteDirectories
    webDirectory = config.get("SitesDirectory","web")
    #Allowed IPs
    webAllowedIP = []
    webAllowedIP = config.get("AllowedIPS","web").replace(" ", "").split(',')
    sshAllowedIP = []
    sshAllowedIP = config.get("AllowedIPS","ssh").replace(" ", "").split(',')
    mysqlAllowedIP = []
    mysqlAllowedIP = config.get("AllowedIPS","mysql").replace(" ", "").split(',')
    psqlAllowedIP = []
    psqlAllowedIP = config.get("AllowedIPS","psql").replace(" ", "").split(',')

    webPorts = []
    sshPorts = []
    mysqlPorts = []
    psqlPorts = []

#Funcion para imprimir mensaje de eror y salir
def printError(message):
    sys.stderr.write("Error: %s" % message)
    sys.exit(1)

def checkOptions(opts):
    if opts.config is None: printError("Please enter the name of the configuration file with -c\n")
    if opts.blacklist is None: printError("Please enter the name of the blacklist file with -b\n")
    if opts.webService is None or opts.webService not in ["apache2","httpd"] : printError("Please enter the name of the WEB service file with -w apache2|httpd\n")

def addOptions():
    parser = OptionParser()
    parser.add_option("-c", "--config", dest="config", default=None, help="Config File")
    parser.add_option("-b", "--blacklist", dest="blacklist", default=None, help="blacklist File")
    parser.add_option("-w", "--webService", dest="webService", default=None, help="web service")
    return parser

def getRunningPorts(webService):
    webPort = commands.getoutput("netstat -natp | column -t | grep "+webService+" | awk '{print $4}' | rev |cut -d':' -f 1 | rev")
    sshPort = commands.getoutput("netstat -natp | column -t | grep     sshd | awk '{print $4}' | rev |cut -d':' -f 1 | rev")
    mysqlPort = commands.getoutput("netstat -natp | column -t | grep  mysqld | awk '{print $4}' | rev |cut -d':' -f 1 | rev")
    psqlPort = commands.getoutput("netstat -natp | column -t | grep postgres | awk '{print $4}' | rev |cut -d':' -f 1 | rev")

    print "Detecting running services: \n"
    for port in webPort.split("\n"):
        if port not in webPorts: webPorts.append(port)
    for port in sshPort.split("\n"):
        if port not in sshPorts: sshPorts.append(port)
    for port in mysqlPort.split("\n"):
        if port not in mysqlPorts: mysqlPorts.append(port)
    for port in psqlPort.split("\n"):
        if port not in psqlPorts: psqlPorts.append(port)

    if webPorts[0] != "" : print "Web Ports "+str(webPorts)
    if sshPorts[0] != "" :print "SSH Port "+str(sshPorts)
    if mysqlPorts[0] != "" :print "MySQL Port "+str(mysqlPorts)
    if psqlPorts[0] != "" :print "postgresql Port "+str(psqlPorts)

    if len(webAllowedIP) > 0 and webPorts[0] != "" :print "\n\nAllowed web IPS from config file: "      +    str(webAllowedIP)
    if len(sshAllowedIP) > 0 and sshPorts[0] != "" :print "Allowed ssh IPS from config file: "      +    str(sshAllowedIP)
    if len(mysqlAllowedIP) > 0 and mysqlPorts[0] != "" :print "Allowed mysql IPS from config file: "      +    str(mysqlAllowedIP)
    if len(psqlAllowedIP) > 0 and psqlPorts[0] != "" :print "Allowed postgresql IPS from config file: "      +    str(psqlAllowedIP)

def getWebAllowed(directory):
    if os.path.isdir(directory):
        files = commands.getoutput("ls "+directory).split("\n")
        #print files
        for f in files:
            print "\nSearching for allowed hosts on: "+f
            #print "grep -i \"Allow from\" "+webDirectory+f+" | column -t | awk '{for(i=3;i<=NF;++i)print $i}'"
            dirs = commands.getoutput("grep -i \"Allow from\" "+webDirectory+f+" | column -t | awk '{for(i=3;i<=NF;++i)print $i}'")
        print "\nAllowed IP from sites files"
        for ip in dirs.split("\n"):
            if "all" not in ip and ip not in webAllowedIP:
                print ip
                webAllowedIP.append(ip)
    else: print directory+" doesn't exist\n"
    print webAllowedIP

def blockingBlacklist(blacklist):
    lines = [line.rstrip('\n') for line in open(blacklist)]
    ipScript.write("#Direcciones bloqueadas por la lista negra\n")
    for ip in lines:
        ipScript.write("iptables -A INPUT -s "+ip+" -j DROP\n")
#Setting up Policy
def settingPolicy(ipScript):
    ipScript.write("#!/bin/sh\n")
    ipScript.write("#Se inicializa el firewall\n")
    ipScript.write("iptables -F\n")
    ipScript.write("iptables -X\n")
    ipScript.write("iptables -Z\n")
    ipScript.write("#Se establece politica restrictiva\n")
    ipScript.write("iptables -P INPUT DROP\n")
    ipScript.write("iptables -P OUTPUT DROP\n")
    ipScript.write("iptables -P FORWARD DROP\n")
    ipScript.write("#Se permiten las conexiones de y hacia el localhost\n")
    ipScript.write("iptables -A INPUT -i lo -j ACCEPT\n")
    ipScript.write("iptables -A OUTPUT -o lo -j ACCEPT\n")

def webPolicy():
    if webPorts[0] != "" and len(webAllowedIP) > 0:
        ipScript.write("#Direcciones permitidas para servicio web\n")
        for port in webPorts:
            for ip in webAllowedIP:
                #print ip
                ipScript.write("iptables -A INPUT -p tcp -s "+ip+" --sport 1024:65535 -d "+serverIP+" --dport "+port+" -m state --state NEW,ESTABLISHED -j ACCEPT\n")
                ipScript.write("iptables -A OUTPUT -p tcp -s "+serverIP+" --sport "+port+" -d "+ip+" --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT\n")

def sshPolicy():
    if sshPorts[0] != "" and len(sshAllowedIP) > 0:
        ipScript.write("#Direcciones permitidas para servicio ssh\n")
        for port in sshPorts:
            for ip in sshAllowedIP:
                #print ip
                ipScript.write("iptables -A INPUT -s "+ip+" -d "+serverIP+" -p tcp --dport "+port+" -j ACCEPT\n")
                ipScript.write("iptables -A OUTPUT -s "+serverIP+"  -d "+ip+" -p tcp --sport "+port+" -j ACCEPT\n")

def mysqlPolicy():
    if mysqlPorts[0] != "" and len(mysqlAllowedIP) > 0:
        ipScript.write("#Direcciones permitidas para servicio mysql\n")
        for port in mysqlPorts:
            for ip in mysqlAllowedIP:
                #print ip
                ipScript.write("iptables -A INPUT -s "+ip+" -d "+serverIP+" -p tcp --dport "+port+" -j ACCEPT\n")
                ipScript.write("iptables -A OUTPUT -s "+serverIP+"  -d "+ip+" -p tcp --sport "+port+" -j ACCEPT\n")

def psqlPolicy():
    if psqlPorts[0] != "" and len(psqlAllowedIP) > 0:
        ipScript.write("#Direcciones permitidas para servicio postgresql\n")
        for port in psqlPorts:
            for ip in psqlAllowedIP:
                #print ip
                ipScript.write("iptables -A INPUT -s "+ip+" -d "+serverIP+" -p tcp --dport "+port+" -j ACCEPT\n")
                ipScript.write("iptables -A OUTPUT -s "+serverIP+"  -d "+ip+" -p tcp --sport "+port+" -j ACCEPT\n")

if __name__ == '__main__':
    reload(sys)
    sys.setdefaultencoding("utf8")
    parser = addOptions()
    opts, args = parser.parse_args()
    checkOptions(opts)
    configFile = opts.config
    blacklistFile = opts.blacklist

    try:
        ipScript = open('iptables.sh','w')
        settingPolicy(ipScript)
        loadConfig(configFile)
        getRunningPorts(opts.webService)
        getWebAllowed(webDirectory)
        webPolicy()
        sshPolicy()
        mysqlPolicy()
        psqlPolicy()
        print "File iptables.sh has been created\n"
        blockingBlacklist(blacklistFile)
        ipScript.close()
    except Exception as e:
        print(e)
