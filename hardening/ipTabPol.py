#!/usr/bin/python
# -*- coding: utf-8 -*-
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
import ipaddress



#Class to manage the color for printing.
class color:
    Red='\033[0;31m'          # Red
    Green='\033[0;32m'        # Green
    Yellow='\033[0;33m'       # Yellow
    Purple='\033[0;35m'       # Purple
    Cyan='\033[0;36m'         # Cyan
    Color_off = '\033[0m'
    Bold = '\033[1m'
    Underline = '\033[4m'
#Función que imprime el banner
def banner():                                                  
    print color.Cyan+"""\n\n             MMMMMMMMMMMMMMMMMMMMMMMMM                  
       MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM            
     MMMMMMMMMMMMMMM           MMMMMMMMMMMMMMM        
     MMMMMM       MMMM       MMMM       MMMMMM         
     M         MMMMMMMM    MMMMMMMMM                    
      MMMMM      MMMMMM    MMMMM        MMMMM           
    MMMMMMMM       MMMM   MMMMMM       MMMMMMMM         
    MMMMMMMM      MMMMMM  MMMMMMMM     MMMMMMMM         
    MMMMMMMMMMMMMMMMM         MMMMMMMMMMMMMMMMM         
    MMMMMMMMMMMMMMM             MMMMMMMMMMMMMMM         
    MMMMMMMMMMMMM   MMMMMMMMMMM   MMMMMMMMMMMMM         
    MMMMMMMMMMMM   MMM MMMMM MMM   MMMMMMMMMMMM         
    MMMMMMMMMMM  MMM       MM  MMM  MMMMMMMMMMM         
    MMMMMMMMMM   MMM       MMM MMM   MMMMMMMMMM         
    MMMMMMMMMM  MMMMM         MMMMM  MMMMMMMMMM         
    MMMMMMMMMM  MMMMMM          MMM  MMMMMMMMMM         
    MMMMMMMMMM  MMMMM  MM       MMM  MMMMMMMMMM         
    MMMMMMMMMM   MMM  MM  MM    MM   MMMMMMMMMM         
    MMMMMMMMMMM  MMM MM MMMMMMMMM   MMMMMMMMMMM         
    MMMMMMMMMMMM   MMMMMMMMMMMMM   MMMMMMMMMMMM         
                     MMMMMMMMM                          
                                                        
    M       M  MM      M     MM      M       M          
    M       M  M M     M     MM     MMM     MM          
    M       M  M  MM   M    M  M    M M    M M          
    M       M  M    M  M   MMMMMM   M  M  M  M          
     M     M   M     MMM  M     MM  M   MM   M         
      M M M    M       M  M      M  M        M         
                                                        
       MMMM      MMMMM      MMMM       MMMMMMMM        
    MM           M          M    M        MM           
    M            M          M    M        MM           
   MM            MMMM       M M           MM           
    M            M          M  MM         MM           
      MMMMMM     MMMMM      M    M        MM


                ipTabPol v1.0\n\n\n\n"""+color.Color_off

#Funcion para cargar la configuracion
def loadConfig(configFile):
    global webPorts, sshPorts, mysqlPorts, psqlPorts
    global webAllowedIP, sshAllowedIP, mysqlAllowedIP, psqlAllowedIP
    global webDirectory, serverIP
    #Cargando configuraciones
    config = ConfigParser.ConfigParser()
    config.read(configFile)

    serverIP = config.get("Server","ip")
    #Ruta de los archivos de configuracion de los sitios habilitados
    webDirectory = config.get("SitesDirectory","web")
    #Direcciones IP permitidas
    webAllowedIP = set([x for x in config.get("AllowedIPS","web").replace(" ", "").split(',') if validateIP(x)])
    sshAllowedIP = set([x for x in config.get("AllowedIPS","ssh").replace(" ", "").split(',') if validateIP(x)])
    mysqlAllowedIP = set([x for x in config.get("AllowedIPS","mysql").replace(" ", "").split(',') if validateIP(x)])
    psqlAllowedIP = set([x for x in config.get("AllowedIPS","psql").replace(" ", "").split(',') if validateIP(x)])
    #Puertos en los que se ejecuta cada servicio
    webPorts = []
    sshPorts = []
    mysqlPorts = []
    psqlPorts = []

#Funcion para imprimir mensaje de eror y salir
def printError(message):
    sys.stderr.write(color.Red+color.Bold+"Error: %s" % message + color.Color_off)
    sys.exit(1)

#Funcion que valida las opciones
def checkOptions(opts):
    if opts.config      is None: printError("Please enter the name of the configuration file with -c\n")
    if opts.blacklist   is None: printError("Please enter the name of the blacklist file with -b\n")
    if opts.webService  is None or opts.webService not in ["apache2","httpd"] : printError("Please enter the name of the WEB service file with -w apache2|httpd\n")

#Funcion que anade las opciones el programa
def addOptions():
    parser = OptionParser()
    parser.add_option("-c", "--config", dest="config", default=None, help="Config File")
    parser.add_option("-b", "--blacklist", dest="blacklist", default=None, help="blacklist File")
    parser.add_option("-w", "--webService", dest="webService", default=None, help="web service")
    return parser

#Funcion que obtiene los poertos en los que los servicios se estan ejecutando
def getRunningPorts(webService):
    webPort   = commands.getoutput("netstat -natp | column -t | grep "+webService+" | awk '{print $4}' | rev |cut -d':' -f 1 | rev")
    sshPort   = commands.getoutput("netstat -natp | column -t | grep     sshd | awk '{print $4}' | rev |cut -d':' -f 1 | rev")
    mysqlPort = commands.getoutput("netstat -natp | column -t | grep  mysqld | awk '{print $4}' | rev |cut -d':' -f 1 | rev")
    psqlPort  = commands.getoutput("netstat -natp | column -t | grep postgres | awk '{print $4}' | rev |cut -d':' -f 1 | rev")

    print color.Cyan+color.Bold+"Detecting running services... \n"+color.Color_off
    for port in webPort.split("\n"):
        if port not in webPorts: webPorts.append(port)
    for port in sshPort.split("\n"):
        if port not in sshPorts: sshPorts.append(port)
    for port in mysqlPort.split("\n"):
        if port not in mysqlPorts: mysqlPorts.append(port)
    for port in psqlPort.split("\n"):
        if port not in psqlPorts: psqlPorts.append(port)

    if webPorts[0]   != "" : print color.Cyan+"\tWeb Ports: \t\t"+', '.join([str(item) for item in webPorts])+color.Color_off
    if sshPorts[0]   != "" : print color.Cyan+"\tSSH Port: \t\t"+', '.join([str(item) for item in sshPorts])+color.Color_off
    if mysqlPorts[0] != "" : print color.Cyan+"\tMySQL Port: \t\t"+', '.join([str(item) for item in mysqlPorts])+color.Color_off
    if psqlPorts[0]  != "" : print color.Cyan+"\tpostgresql Port: \t"+', '.join([str(item) for item in psqlPorts])+color.Color_off

    print color.Cyan+color.Bold+"\n\nDetecting allowed ip addresses from the configuration file... \n"+color.Color_off
    if len(webAllowedIP)    > 0 and webPorts[0]   != "" : print '\t'+color.Cyan+"Allowed for web service: \t"+', '.join([str(item) for item in webAllowedIP])+color.Color_off
    if len(sshAllowedIP)    > 0 and sshPorts[0]   != "" : print '\t'+color.Cyan+"Allowed for ssh service: \t"+', '.join([str(item) for item in sshAllowedIP])+color.Color_off
    if len(mysqlAllowedIP)  > 0 and mysqlPorts[0] != "" : print '\t'+color.Cyan+"Allowed for mysql:  \t\t"  +', '.join([str(item) for item in mysqlAllowedIP])+color.Color_off
    if len(psqlAllowedIP)   > 0 and psqlPorts[0]  != "" : print '\t'+color.Cyan+"Allowed for postgresql: \t"+', '.join([str(item) for item in psqlAllowedIP])+color.Color_off  

#Funcion que valida una direccion ip o red 
def validateIP(ip):
    try: 
        ipaddress.ip_network(unicode(ip))
        return True
    except ValueError:
        return False

#Funcion para obtener las direcciones ip permitidas de los archivos de configuracion 
def getWebAllowed(directory):
    print color.Cyan+color.Bold+"\n\nDetecting allowed hosts on sites enabled... \n"+color.Color_off
    if os.path.isdir(directory):
        files = commands.getoutput("ls "+directory).split("\n")
        for f in files:
            print color.Cyan+"\tFile: "+f+color.Color_off
            dirs = commands.getoutput("grep -i \"Allow from\" "+webDirectory+f+" | column -t | awk '{for(i=3;i<=NF;++i)print $i}'")
            for ip in dirs.split("\n"):
                if "all" not in ip and ip not in webAllowedIP and validateIP(ip):
                    print color.Green+"\t\t"+ip+color.Color_off
                    webAllowedIP.append(ip)
    else: print "\t"+color.Red+color.Bold+directory+" doesn't exist\n"+color.Color_off

#Funcion que crea los comandos para bloquear las direcciones ip de la lista negra
def blockingBlacklist(blacklist):
    lines = [line.rstrip('\n') for line in open(blacklist)]
    ipScript.write("#Direcciones bloqueadas por la lista negra\n")
    for ip in set(lines):
        ipScript.write("iptables -A INPUT -s "+ip+" -j DROP\n")

#Setting up Policy
def settingPolicy(ipScript):
    ipScript.write("#!/bin/sh\n")
    ipScript.write("#Se hace un respaldo de las reglas\n")
    ipScript.write("iptables-save > rules.old\n")
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

#Funcion que establece la politica del servicio web
def webPolicy():
    if webPorts[0] != "" and len(webAllowedIP) > 0:
        ipScript.write("#Direcciones permitidas para servicio web\n")
        for port in webPorts:
            for ip in webAllowedIP:
                ipScript.write("iptables -A INPUT -p tcp -s "+ip+" --sport 1024:65535 -d "+serverIP+" --dport "+port+" -m state --state NEW,ESTABLISHED -j ACCEPT\n")
                ipScript.write("iptables -A OUTPUT -p tcp -s "+serverIP+" --sport "+port+" -d "+ip+" --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT\n")

#Funcion que establece la politica del servicio SSH
def sshPolicy():
    if sshPorts[0] != "" and len(sshAllowedIP) > 0:
        ipScript.write("#Direcciones permitidas para servicio ssh\n")
        for port in sshPorts:
            for ip in sshAllowedIP:
                ipScript.write("iptables -A INPUT -s "+ip+" -d "+serverIP+" -p tcp --dport "+port+" -j ACCEPT\n")
                ipScript.write("iptables -A OUTPUT -s "+serverIP+"  -d "+ip+" -p tcp --sport "+port+" -j ACCEPT\n")

#Funcion que establece la politica del servicio mysql
def mysqlPolicy():
    if mysqlPorts[0] != "" and len(mysqlAllowedIP) > 0:
        ipScript.write("#Direcciones permitidas para servicio mysql\n")
        for port in mysqlPorts:
            for ip in mysqlAllowedIP:
                ipScript.write("iptables -A INPUT -s "+ip+" -d "+serverIP+" -p tcp --dport "+port+" -j ACCEPT\n")
                ipScript.write("iptables -A OUTPUT -s "+serverIP+"  -d "+ip+" -p tcp --sport "+port+" -j ACCEPT\n")

#Funcion que establece la politica del servicio postgresql
def psqlPolicy():
    if psqlPorts[0] != "" and len(psqlAllowedIP) > 0:
        ipScript.write("#Direcciones permitidas para servicio postgresql\n")
        for port in psqlPorts:
            for ip in psqlAllowedIP:
                ipScript.write("iptables -A INPUT -s "+ip+" -d "+serverIP+" -p tcp --dport "+port+" -j ACCEPT\n")
                ipScript.write("iptables -A OUTPUT -s "+serverIP+"  -d "+ip+" -p tcp --sport "+port+" -j ACCEPT\n")


if __name__ == '__main__':
    reload(sys)
    sys.setdefaultencoding("utf8")
    parser = addOptions()
    opts, args = parser.parse_args()
    checkOptions(opts)
    banner()
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
        blockingBlacklist(blacklistFile)
        ipScript.close()
        print color.Green+color.Bold+"\n\nFile iptables.sh has been created\n"+ color.Color_off
    except Exception as e:
        print(e)