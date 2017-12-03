#!/usr/bin/python
# -*- coding: utf-8 -*-
#Log AnalyCERT v2.0
#Castro Rendón Virgilio
#Parra Arroyo Fernando Marcos
#Arrieta Jiménez Diana Laura

import subprocess
import sys, os
import optparse
import os.path
import gzip
import csv
import re
import urllib
from datetime import datetime
from collections import defaultdict
from itertools import chain
import plotly
import plotly.graph_objs as go
from geoip import geolite2

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


                Log AnalyCERT v2.0\n\n\n\n"""+color.Color_off


#variables to count in mail logs
count_mail = 0
count_send = 0
count_received = 0
count_rejected = 0
count_inSysStorage = 0
count_connections = 0
dest_dict = dict()
ip_dict = dict()
senders_dict = {}
rejected_dict = {}
fatal_mail = []
panic_mail = []
error_mail = []
warnings_mail = []
##variables used to count in the ssh logs
failure_IPS = {}
failure_USRS = {}
failedTries = {}
failed_attempts = 0
logs = {}
sshTries = 20
#variables used to count in the postgresql logs
failedTries = {}
error_logs = {}
error_lines = []
#variables used to count in the ftp logs
downloaded_files = {}
failure_ips_ftp = {}
failure_usr_ftp = {}
failedTries_ftp = {}
uploaded_ftp = []
downloaded_ftp = []
login_fallido = 0
#variables used to count in the mysql logs
failedTries_mysql = {}
#Variables to count errors in php logs
error_fatal = 0
error_parse = 0
error_warning = 0
error_notice = 0
error_deprecated = 0

bruteForce = dict()
crawlers = dict()
ip_attacks_total = {}
ips = set()
start_time = ''
lines = 0
detected_attacks = []
detected_php_info = []
verbose = ''
a_dict = {'xss':'Cross-Site Scripting',
        'dt': 'Directory Transversal',
        'lfi':'Local File Inclusion',
        'rfi':'Remote File Inclusion',
        'bf':'Brute Force',
        'sqli':'SQL Injection',
        'csrf':'Cross-Site Request Forgery',
        'craw':'Crawler'}
#datetime.strptime(var,'%d/%b/%Y:%H:%M:%S')

#This dictionary will hold all the events in determined interval. They time will be the key and the value a list of Bfrecord objects
bf_attacks = {}

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


#Class to manage each record in the php log file.
class sshLog:
    def __init__(self, usr):
        self.usr = usr
        self.logs = []
        self.fail_logs = []
        self.succ_logs = []
        self.ips = []
        self.commands = []

#Class to manage each record in the php log file.
class phpLog(object):
    def __init__(self, c_error, ip_client, desc, date, file_ref):
    	self.c_error = c_error
    	self.ip_client = ip_client
    	self.desc = desc
    	self.date = date
    	self.file_ref = file_ref
    def __str__(self):
        return '[%s] [%s] [%s] [%s] [%s] \n' % (self.c_error, self.ip_client, self.desc, self.date, self.file_ref)

#Class to manage each record in the ftp log file.
class ftpLog(object):
    def _init_(self, state, ip_client, user, date, file_ref):
    	self.state = state
    	self.ip_client = ip_client
    	self.user = user
    	self.date = date
    	self.file_ref = file_ref
    def __str__(self):
        return '[%s] [%s] [%s] [%s] [%s] \n' % (self.state, self.ip_client, self.user, self.date, self.file_ref)


#Class to manage each record in the web log files. If it's consider an attack, will saved using this class.
#This class also works to save the records for BF analysis.
class Attack(object):
    def __init__(self, attack, ip, date, request, code, agent):
        self.attack = attack
        self.ip = ip
        self.date = date
        self.request = request
        self.code = code
        self.agent = agent

    def __str__(self):
        return '[%s] [%s] [%s] [%s] [%s] [%s]\n' % (self.attack, self.ip, self.date, self.request, self.code, self.agent)

#Writes in stderr the message and exits
def printError(msg, exit):
    sys.stderr.write(color.Red+color.Bold+'Error:\t%s\n' % msg+color.Color_off)
    if exit:
        sys.exit(1)

#Adds the options that the script accepts
def addOptions():
    parser = optparse.OptionParser()
    parser.add_option('--apache-log', dest='apache_log', default=None, help='Apache access log file to analyze. If present, won\'t use any file specified in the configuration.')
    parser.add_option('--nginx-log', dest='nginx_log', default=None, help='Nginx access log file to analyze. If present, won\'t use any file specified in the configuration.')
    parser.add_option('--postgresql-log', dest='postgresql_log', default=None, help='Postgresql log file to analyze. If present, won\'t use any file specified in the configuration.')
    parser.add_option('--mysql-log', dest='mysql_log', default=None, help='Mysql log file to analyze. If present, won\'t use any file specified in the configuration.')
    parser.add_option('--ssh-log', dest='ssh_log', default=None, help='SSH log file to analyze. If present, won\'t use any file specified in the configuration.')
    parser.add_option('--php-log', dest='php_log', default=None, help='PHP log file to analyze. If present, won\'t use any file specified in the configuration.')
    parser.add_option('--ftp-log', dest='ftp_log', default=None, help='FTP log file to analyze. If present, won\'t use any file specified in the configuration.')
    parser.add_option('--mail-log', dest='mail_log', default=None, help='Mail log file to analyze. If present, won\'t use any file specified in the configuration.')
    parser.add_option('--rot-max', dest='rot_max', default=None, help='Max number of rotated files to analyze.')
    parser.add_option('--rot-compressed', dest='compressed', default=None, action="store_true", help='If indicated, means that rotated logs are compressed.')
    parser.add_option('-g','--graph', dest='graph', default=None, action="store_true", help='If indicated, the results will be graphed')
    parser.add_option('-v','--verbose', dest='verbose', default=None, action="store_true", help='If indicated, the programm will show the progress in standard output.')
    parser.add_option('-o','--output', dest='output', default=None,  help='Indicates the name of the report file.')
    parser.add_option('-r','--log-rotated', dest='rotated', default=None, action="store_true", help='If indicated, will look for rotated logs.')
    parser.add_option('-c','--config-file', dest='config', default=None, help='Configuration file for the script.')
    parser.add_option('-a','--attack-type', dest='attacks', default=None, help='Attack types to detect. [lfi,rfi,sqli,xss,csrf,dt,bf,craw]')
    parser.add_option('-s','--services', dest='services', default=None, help='Services to analyze. [apache,nginx,postgresql,mysql,ssh,php,ftp,mail]')
    opts,args = parser.parse_args()
    return opts



#Check if options are correct. If they are not, prints an error and exits
def checkOptions(opts):
    if opts.config is None:
        printError('You must specify a configuration file.', True)

    if not os.path.isfile(opts.config):
        printError('The specified configuration file does not exist.', True)

    if opts.attacks is not None:
        for a in opts.attacks.split(','):
            if a not in ['lfi','rfi','sqli','xss','csrf','dt','bf','craw']:
                printError('Could not understand the attack type %s. Try using: lfi,rfi,sqli,xss,csrf,dt,bf or craw' % a, True)

    if opts.services is not None:
        for service in opts.services.split(','):
            if service not in ['apache','nginx','postgresql','mysql','ssh','php','ftp','mail']:
                printError('Could not understand the service %s. Try using: apache, nginx, postgresql, mysql, ssh, php, ftp, mail' % service, True)



#Reads and parses the configuration file
def readConfigFile(config):
    #These are the dictionaries used to store the info from the config file
    log_conf = {'apache_log':[], 'nginx_log':[], 'postgresql_log':[], 'mysql_log':[], 'ssh_log':[], 'php_log':[],'ftp_log':[], 'mail_log':[]}
    rules = {'rfi_rule':[], 'lfi_rule':[], 'sqli_rule':[], 'xss_rule':[], 'csrf_rule':[], 'dt_rule':[], 'crawler_rule':[], 'bf_seconds':'', 'bf_tries':''}
    exec_conf = {'rfi': '', 'lfi':'', 'sqli':'', 'xss':'', 'csrf':'', 'dt':'', 'bf':'', 'craw':'', 'apache':'', 'nginx':'', 'mysql':'', 'ssh':'', 'php':'', 'ftp':'', 'mail':'', 'postgresql':'', 'graph':'', 'verbose':'', 'output':''}
    rot_conf = {'rotated':'', 'compressed':'', 'rot_ext':'', 'rot_max':''}

    with open(config,"r") as c:
        for line in c.readlines():
            line = line.strip()
            if re.match(r'^\s*$', line): continue #If line is empty, continue with the next one
            if line[0] == '#': continue
            option = map(lambda x: x.strip() ,line.split('=',1)) #Gets the first and second element from option and quits blank spaces

            if option[0] in log_conf.keys():    #Determines if the specified option is valid
                log_conf[option[0]].append(option[1])   #Appends the log file to the list of log files

            elif option[0] in rules.keys():
                if option[0] in ['bf_seconds', 'bf_tries']:
                    rules[option[0]] = int(option[1])
                else:
                    rules[option[0]].append(option[1][1:-1])

            elif option[0] in exec_conf.keys():
                exec_conf[option[0]] = option[1]    #Makes the specified option part of the dictionary

            elif option[0] in rot_conf.keys():
                rot_conf[option[0]] = option[1]    #Makes the specified option part of the dictionary
            else:

                printError('Could not understand the %s option in the configuration file.' % option[0], True)
    return log_conf, exec_conf, rules, rot_conf



#Checks if the options specified for the execution are correct
def setExecConf(exec_dict):
    for key in exec_dict:
        if exec_dict[key].lower() in ['true','on','1']:
            exec_dict[key] = True
        elif exec_dict[key].lower() in ['false','off','0']:
            exec_dict[key] = False
        elif key == 'output' and exec_dict[key] != '':
            continue
        else:
            printError('Wrong configuration file.\'%s\' is not a valid option for \'%s\'.' % (exec_dict[key],key), True)
    return exec_dict



#Determines in which distro is been executed the script
def checkDistro():
    with open('/etc/os-release','r') as i:
        output = i.read().lower()
        if 'kali' in output or 'ubuntu' in output or 'debian' in output:
            return 'debian'
        elif 'centos' in output:
            return 'centos'
        else:
            printError('The used distro is not supported by this script', True)



#Determines which services are running
def checkServices(distro):
    services = []
    if distro == 'debian':
        proc = subprocess.check_output('service --status-all 2> /dev/null', shell = True).lower()
    else:
        proc = subprocess.check_output('systemctl list-unit-files 2> /dev/null', shell = True).lower()

    if 'apache' in proc or 'httpd' in proc: services.append('apache')
    if 'nginx' in proc: services.append('nginx')
    if 'mysql' in proc or 'mariadb' in proc: services.append('mysql')
    if 'ssh' in proc: services.append('ssh')
    if 'ftp' in proc: services.append('tfp')
    if 'php' in proc: services.append('php')
    if 'mail' in proc: services.append('mail')
    if 'postgresql' in proc: services.append('postgresql')
    return services



#Sets the verbose mode and deletes the contents of the report file
def setGlobalConf(exec_conf):
    global verbose
    verbose = exec_conf['verbose']
    with open(exec_conf['output'],'w') as r :
        r.write('Log AnalyCERT v2.0\n\n')
    with open(exec_conf['output']+'.ips','w') as r :
        pass
    with open(exec_conf['output']+'.ev','w') as r :
        r.write('Log AnalyCERT v2.0')



#Sets the final configuration, with the configuration file and the command-line options
def setFinalExecConf(exec_conf, cmd_opts):
    available_attacks = ['lfi','rfi','sqli','xss','csrf','dt','bf','craw']
    if cmd_opts.attacks is not None:
        for attack in available_attacks:
            exec_conf[attack] = True if attack in cmd_opts.attacks.split(',') else False

    available_services = ['apache','nginx','postgresql','mysql','ssh','php','ftp','mail']
    if cmd_opts.services is not None:
        for service in available_services:
            exec_conf[service] = True if service in cmd_opts.services.split(',') else False

    if cmd_opts.rotated is not None:
        exec_conf['rotated'] = True
    if cmd_opts.graph is not None:
        exec_conf['graph'] = True
    if cmd_opts.verbose is not None:
        exec_conf['verbose'] = True
    if cmd_opts.output is not None:
        exec_conf['output'] = cmd_opts.output
    return exec_conf


#changes "on" or "off" values for actual boolean values
#Changes config opts for cmd opts
def setFinalRotConf(rot_conf, cmd_opts):
    if rot_conf['rotated'].lower() in ['true','on','0']:
        rot_conf['rotated'] = True
    elif rot_conf['rotated'].lower() in ['false','off','1']:
        rot_conf['rotated'] = False
    else: printError('Wrong value for rotated option in configuration file. Try using on or off', True)

    if rot_conf['compressed'].lower() in ['true','on','0']:
        rot_conf['compressed'] = True
    elif rot_conf['compressed'].lower() in ['false','off','1']:
        rot_conf['compressed'] = False
    else: printError('Wrong value for compressed option in configuration file. Try using on or off.', True)

    try:
        rot_conf['rot_max'] = int(rot_conf['rot_max'])
        if rot_conf['rot_max'] < 0: raise ValueError('Wrong value')
    except:
        printError('Wrong value for rot_max option in configuration file. It must be a positive integer', True)
    if cmd_opts.compressed is not None: rot_conf['compressed'] = cmd_opts.compressed
    if cmd_opts.rotated is not None: rot_conf['rotated'] = cmd_opts.rotated
    if cmd_opts.rot_max is not None: rot_conf['rot_max'] = int(cmd_opts.rot_max)
    return rot_conf



#Sets the final logs to look for with the configuration file and the command-line options
def setFinalLogConf(log_conf, cmd_opts):
    if cmd_opts.apache_log is not None:
        log_conf['apache_log'] = cmd_opts.apache_log.split(',')
    if cmd_opts.nginx_log is not None:
        log_conf['nginx_log'] = cmd_opts.nginx_log.split(',')
    if cmd_opts.postgresql_log is not None:
        log_conf['postgresql_log'] = cmd_opts.postgresql_log.split(',')
    if cmd_opts.mysql_log is not None:
        log_conf['mysql_log'] = cmd_opts.mysql_log.split(',')
    if cmd_opts.ssh_log is not None:
        log_conf['ssh_log'] = cmd_opts.ssh_log.split(',')
    if cmd_opts.ftp_log is not None:
        log_conf['ftp_log'] = cmd_opts.ftp_log.split(',')
    if cmd_opts.php_log is not None:
        log_conf['php_log'] = cmd_opts.php_log.split(',')
    if cmd_opts.mail_log is not None:
        log_conf['mail_log'] = cmd_opts.mail_log.split(',')
    return log_conf



#Determines in log files that must be analyzed, exist
def checkLogFiles(log_files):
    for log_file in log_files:
        if not os.path.isfile(log_file): printError('The specified log file does not exist (%s)' % log_file, True)



#Returns a list of the existing rotated logs.
#To construct the name of the rotated files, needs the extension, a secuencial number and a list of the files (recursive)
def getRotatedLogs(log, extension, rot_max, number, existing_files):
    if number == 0:
        ext = extension.replace('.{n}.gz','')
    else:
        ext = extension.replace('{n}',str(number))
    log_file = log+ext
    if not os.path.isfile(log_file) and number > rot_max-1:
        return existing_files
    else:
        if os.path.isfile(log_file):
            existing_files.append(log_file)
        return getRotatedLogs(log, extension, rot_max, number+1, existing_files)

#With the global dictionary, determines if there is an attack.
def determineBfAttack(seconds, tries):
    global bf_attacks
    sorted_bf_attacks = list(bf_attacks.keys())
    sorted_bf_attacks.sort()
#    while (sorted_bf_attacks[-1] - sorted_bf_attacks[0]).seconds >= seconds:
#        del bf_attacks[sorted_bf_attacks[0]] #Removes the first element of the dictionary using the sorted list
#        sorted_bf_attacks = sorted_bf_attacks[1:] #Removes the key from the list
    if (sorted_bf_attacks[-1] - sorted_bf_attacks[0]).seconds < seconds:
        return False

    larger_list = [] #A list of the lists of all the attacks.
    for time in bf_attacks: larger_list += bf_attacks[time]

    bf_attacks = {}
    ip_filter = {} #Once the list is complete, it must be filtered by the IPs
    for a in larger_list:
        if a.ip not in ip_filter.keys():
            ip_filter[a.ip] = {}
        else:
            if a.request not in ip_filter[a.ip].keys():
                ip_filter[a.ip][a.request] = [a]
            else:
                ip_filter[a.ip][a.request].append(a)

    for ip in ip_filter:
        for url in ip_filter[ip]:
            if len(ip_filter[ip][url]) >= tries:
                return ip_filter[ip][url][0]
    return False


#Detects if the request corresponds to an attack
def findAttack(attack_rules, reg, log_type):
    if log_type == 'ssh_log':
        #print "Analyzing SSH"
        if "Accepted password for" in reg.group('request'):
            print reg.group('request')
    elif log_type == 'php_log':
        print "Analyzing PHP"
    elif log_type == 'ftp_log':
        print "Analyzing FTP"
    elif log_type == 'mail_log':
        print "Analyzing mail"
    else:
        url_decod = {}
        if reg.group('code') == "404": bruteForce[(reg.group('code'),reg.group('request'))] = bruteForce.get((reg.group('code'),reg.group('request')) , 0) + 1
        global bf_attacks
        unquoted = urllib.unquote(reg.group('request'))
        for attack in attack_rules:
            if log_type == 'postgresql_log':
                bf_time = datetime.strptime(reg.group('date'), '%Y-%m-%d %H:%M:%S') #Converts string into datetime object
                attack_obj = Attack(attack, reg.group('ip'), reg.group('date'), unquoted, reg.group('code'), '')
            else:
                bf_time = datetime.strptime(reg.group('date'), '%d/%b/%Y:%H:%M:%S') #Converts string into datetime object
                attack_obj = Attack(attack, reg.group('ip'), reg.group('date'), unquoted, reg.group('code'), reg.group('agent'))

            if attack == 'bf':
                if bf_time in bf_attacks.keys(): #Adds the event i the global dictionary. After that, calls a function to determine if the was an actual attack
                    bf_attacks[bf_time].append(attack_obj)
                else:
                    bf_attacks[bf_time] = [attack_obj]
                bf_attack = determineBfAttack(attack_rules['bf'][0], attack_rules['bf'][1])
                if bf_attack != False:
                    return bf_attack
            else:
                for rule in attack_rules[attack]:
                    match = re.search(rule, unquoted)
                    if match is not None:
                        return attack_obj
                else:
                    #detectAgent(reg.group('ip'), reg.group('date'), unquoted, reg.group('code'), reg.group('agent'))
                    match = re.search(rule, reg.group('agent'))
                    if match is not None:
                        crawlers[(reg.group('agent'))] = crawlers.get((reg.group('agent')) , 0) + 1
                        return attack_obj



#Defines all the fields that are used in the log file
def parseLine(log_type, line, attack_rules):
    global lines
    lines += 1
    log_regex = { 'apache_log':r'(?P<ip>^(([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.){3}([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5]))[\s\-]+\[(?P<date>[^\s]+)[^\"]+\"(?P<method>[^\s]+)\s+(?P<request>[^\s]+)\s+[^\"]+\"\s(?P<code>\w+)[^\"]+\"(?P<name>[^\"]+)\"\s+\"(?P<agent>[^\"]+)',
            'nginx_log':r'(?P<ip>^(([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.){3}([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5]))[\s\-]+\[(?P<date>[^\s]+)[^\"]+\"(?P<method>[^\s]+)\s+(?P<request>[^\s]+)\s+[^\"]+\"\s(?P<code>\w+)[^\"]+\"(?P<name>[^\"]+)\"\s+\"(?P<agent>[^\"]+)',
            'postgresql_log':r'^(?P<date>[^\s]+\s[^\s]+)[^\[]+\[[^\s]+\s(?P<request>[^\s]+)\s(?P<code>[^:]+):[^\"]+\"(?P<ip>(([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.){3}([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])).+$',
            'ssh_log':r'(?P<date>^[A-Za-z]{3} \d{2} \d{2}:\d{2}:\d{2}) (?P<code>[a-z]+) (?P<request>.*)',
            'php_log':r'.*',
            'ftp_log':r'.*',
            'mail_log':r'.*',
            'mysql_log':r'.*'

}
    reg = re.match(log_regex[log_type], line)

    if reg is not None:
#        print "%s\t\t%s\t%s\t%s\t%s\t%s" % (reg.group('ip'), reg.group('date'), reg.group('request'), reg.group('code'), reg.group('name'), reg.group('agent'))
        attack = findAttack(attack_rules, reg, log_type)
        if attack is not None:
            detected_attacks.append(attack)

#Reads the file using open or gzip.open
def readLog(log_type, log, attack_rules, compressed = False):
    if compressed and log.endswith("gz"):
        with gzip.open(log, 'r') as i:
            if log_type == 'php_log': analyzePhpLogs(i)
            if log_type == 'ftp_log': analyzeFtpLogs(i)
            if log_type == 'mail_log': analyzeMailLogs(i)
            if log_type == 'postgresql_log': analyzePostgresLogs(i)
            if log_type == 'mysql_log' : analyzeMysqlLogs(i)
            if log_type == 'ssh_log' : analyzeSshLogs(i)  
            for l in i.readlines():
                parseLine(log_type, l, attack_rules)
    else:
        with open(log, 'r') as i:
            if log_type == 'php_log': analyzePhpLogs(i)
            if log_type == 'ftp_log': analyzeFtpLogs(i)
            if log_type == 'mail_log': analyzeMailLogs(i)
            if log_type == 'postgresql_log': analyzePostgresLogs(i)
            if log_type == 'mysql_log' : analyzeMysqlLogs(i)  
            if log_type == 'ssh_log' : analyzeSshLogs(i)  
            for l in i.readlines():
                parseLine(log_type, l, attack_rules)


def analyzeMailLogs(log_file):
    e_fatal = []
    e_warning = []
    e_error = []
    e_panic = []

    global lines
    global count_mail
    global count_send
    global count_received
    global count_rejected
    global count_inSysStorage
    global count_connections
    global dest_dict
    global ip_dict
    global senders_dict
    global rejected_dict
    global fatal_mail
    global panic_mail
    global error_mail
    global warnings_mail


    for line in log_file.readlines():
        lines = lines +1
        if re.search("postfix",line):
            if re.search("fatal: ",line):
                e_fatal.append(re.search("(fatal: )(.+)",line).group(2))
                fatal_mail.append(line)
            if re.search("warning",line):
                e_warning.append(re.search("(warning: )(.+)",line).group(2))
                warnings_mail.append(line)
            if re.search("error: ",line):
                e_error.append(re.search("(error: )(.+)",line).group(2))
                error_mail.append(line)
            if re.search("panic: ",line):
                e_panic.append(re.search("(panic: )(.+)",line).group(2))
                panic_mail.append(line)
            if re.search("smtpd.+connect from",line):
                count_connections += 1
                ip_conn = re.search("(connect from.+\[)(.+)(\])",line).group(2)
                if ip_conn  is not None: ip_dict[ip_conn] = ip_dict.get(ip_conn , 0) + 1
            if re.search("smtp.+sent",line):
                count_send += 1
                destino = re.search("(to=<)(.+)(>,)",line).group(2)
                if destino  is not None: dest_dict[destino] = dest_dict.get(destino , 0) + 1
            if re.search("relay=local.+status=sent",line):
                count_received += 1
            if re.search("qmgr.+from=<",line):
                remitente = re.search("(from=<)(.+)(>,)",line).group(2)
                if remitente  is not None: senders_dict[remitente] = senders_dict.get(remitente , 0) + 1
            if re.search("reject",line):
                count_rejected += 1
                if re.search("from=<",line) is not None:
                    rejected = re.search("(from=<)(.+)(> to=)",line).group(2)
                    if rejected  is not None: rejected_dict[rejected] = rejected_dict.get(rejected , 0) + 1
            if re.search("Insufficiented system storage",line):
                count_inSysStorage += 1


def analyzeFtpLogs(log_file):
    cliente_IP = []
    linea_ftp = []
    upload = 0
    download  = 0
    login_exitoso = 0
    failed = []

    global login_fallido
    global uploaded_ftp
    global downloaded_ftp 
    global lines
    global downloaded_files
    global failure_ips_ftp
    global failure_usr_ftp
    global failedTries_ftp


    for line in log_file.readlines():
        lines = lines +1
        state = ' '.join(line.split()[8:10]).strip(":")
        if not re.search ("Client",state):
            linea_ftp.append(line)
            cliente_IP.append(re.search(r'(\d{1,3}\.){3}\d{1,3}',line).group(0))
            if re.search("OK UPLOAD",state):
                upload +=  1
            if re.search ("OK DOWNLOAD",state):
                download +=  1
            if re.search("OK LOGIN",state):
                login_exitoso +=1
            if re.search("FAIL LOGIN",state):
                login_fallido +=  1

                tmp = re.search(r'(?P<date>^[A-Za-z]{3}.*[A-Za-z]{3}.*\d{1,2}.*\d{1,2}:\d{2}):\d{2} (?P<year>\d{4}).*(?P<IP>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)', line)
                if tmp is not None:
                    date = tmp.group('date')+" "+tmp.group('year')
                    failure_ips_ftp[tmp.group('IP')] = failure_ips_ftp.get(tmp.group('IP') , 0) + 1
                    failedTries_ftp[(date,tmp.group('IP'))] = failedTries_ftp.get((date,tmp.group('IP')) , 0) + 1


    cliente_IP =  set(cliente_IP)

    for client in cliente_IP :
        for line in linea_ftp:
            if re.search(client,line):
                state = ' '.join(line.split()[8:10]).strip(":")
                file_ref = " "
                user = (line.split()[7]).strip("[").strip("]")
                date = ' '.join(line.split()[0:5])
                if re.search("DOWNLOAD",state):
                    file_ref = line.split(",")[1]
                    downloaded_files[file_ref] = downloaded_files.get(file_ref , 0) + 1
                    downloaded_ftp.append(line)
                if re.search("UPLOAD",state):
                    file_ref = line.split(",")[1]
                    uploaded_ftp.append(line)
                if user  is not None: failure_usr_ftp[user] = failure_usr_ftp.get(user , 0) + 1

#get the country of an IP
def getCountry(IP):
    match = geolite2.lookup(IP)
    if match is not None:
        return match.country
    return "Unknown"

#Get the user from log line
def getUsr(line):
    usr = None
    if "Accepted password" in line:
        usr = re.search(r'(\bfor\s)(\w+)', line)
    elif "sudo:" in line:
        usr = re.search(r'(sudo:\s+)(\w+)', line)
    elif "authentication failure" in line:
        usr = re.search(r'USER=\w+', line)
    elif "for invalid user" in line:
        usr = re.search(r'(\buser\s)(\w+)', line)
    elif "Failed password" in line:
        usr = re.search(r'(\bfor\s)(\w+)', line)
    elif "Invalid user" in line:
        usr = re.search(r'(\buser\s)(\w+)', line)
    if usr is not None:
        return usr.group(2)


def getIP(line):
    ip = re.search(r'(\bfrom\s)(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)', line)
    if ip is not None:
        return ip.group(2)

def getDate(line):
#   date = re.search(r'^[A-Za-z]{3}\s*[0-9]{1,2}\s[0-9]{1,2}:[0-9]{2}:[0-9]{2}', line)
    date = re.search(r'^[A-Za-z]{3}\s*[0-9]{1,2}\s[0-9]{1,2}:[0-9]{2}', line)
    if date is not None:
        return date.group(0)

def getCmd(line):
    cmd = re.search(r'(\bCOMMAND=)(.+?$)', line)
    if cmd is not None:
        return cmd.group(2)

def analyzeSshLogs(log_file):
    global lines
    global failure_IPS 
    global failure_USRS 
    global failedTries
    global failed_attempts
    global logs

    for line in log_file.readlines():
        lines = lines +1


        if "Accepted password for" in line:
            usr = getUsr(line)

            if not usr in logs:
                logs[usr] = sshLog(usr)

            ip = getIP(line)

            if not ip in logs[usr].ips:
                logs[usr].ips.append(ip)
            logs[usr].succ_logs.append(line.rstrip('\n'))
            logs[usr].logs.append(line.rstrip('\n'))

        elif "Failed password for" in line:
            usr = getUsr(line)
            if not usr in logs:
                logs[usr] = sshLog(usr)

            ip = getIP(line)

            failure_IPS[(ip)] = failure_IPS.get((ip) , 0) + 1

            if not ip in logs[usr].ips:
                logs[usr].ips.append(ip)
            logs[usr].fail_logs.append(line.rstrip('\n'))
            logs[usr].logs.append(line.rstrip('\n'))


        elif ":auth): authentication failure;" in line:
            usr = re.search(r'(\blogname=)(\w+)', line)
            if usr is not None:
                usr = usr.group(2)
            if "(sshd:auth)" in line:
                usr = getUsr(line)
                if not usr in logs:
                    logs[usr] = sshLog(usr)
                logs[usr].ips.append(getIP(line))
            else:
                if not usr in logs:
                    logs[usr] = sshLog(usr)
            logs[usr].fail_logs.append(line.rstrip('\n'))
            logs[usr].logs.append(line.rstrip('\n'))
        elif "sudo:" in line:
            usr = getUsr(line)
            if not usr in logs:
                logs[usr] = sshLog(usr)

            cmd = getCmd(line)
            if cmd is not None:
                if not cmd in logs[usr].commands:
                    logs[usr].commands.append(cmd)
            logs[usr].logs.append(line.rstrip('\n'))

    
    names=[]
    for i in logs:
        if i is not None:
            names.append(i)
            failed_attempts = failed_attempts + len(logs[i].fail_logs)
            for reg in logs[i].fail_logs:
                failedTries[(getIP(reg),getDate(reg))] = failedTries.get((getIP(reg),getDate(reg)) , 0) + 1

    names = sorted(names, key=str.lower)

    for user in names:
#       print "_"*40
#       print "User \'%s\'"%user
#       print "  Failed connections: "+str(len(LOGS[user].fail_logs))
        failure_USRS[user] = len(logs[user].fail_logs)
        #for fail in LOGS[user].fail_logs:
        #   print "\t", fail
#       print "  Succeded connections: "+str(len(LOGS[user].succ_logs))
        #for succ in LOGS[user].succ_logs:
        #   print "\t", succ
#       print "  Associated IPs:"
#       for ip in LOGS[user].ips:
#           print "\t", ip
#       print "  Commands"
#       for comm in LOGS[user].commands:
#           print "\t", comm




def analyzePostgresLogs(log_file):
    global lines
    logs = []
    global error_lines 
    triesPostgresql = 20

    global failedTries 
    global error_logs 
    connections = []

    for line in log_file.readlines():
        lines = lines +1
        if re.match(".*password authentication failed for user.*", line) is not None:
            badIP = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
            fecha = re.search(r'\d\d\d\d-\d\d-\d\d', line)
            hora = re.search(r'\d\d:\d\d', line)
            user_tmp = re.search(r'(([A-Z0-9a-z_-]+)@([A-Za-z0-9_-]+))', line)
            user = user_tmp.group(2) if user_tmp else None
            db = user_tmp.group(3) if user_tmp else None
            if badIP  is not None and user is not None:
                failedTries[(badIP.group(),fecha.group(),hora.group(),user,db)] = failedTries.get((badIP.group(),fecha.group(),hora.group(),user,db) , 0) + 1
        if re.match(".*ERROR:.*", line) is not None:
            tmp = re.search(r'@(.+) ERROR:  (.+)', line)
            error_line =  tmp.group(1) if tmp else None
            db =  tmp.group(2) if tmp else None
            if error_line  is not None:
                error_logs[(error_line,db)] = error_logs.get((error_line,db) , 0) + 1
            error_lines.append(line.replace('\n',''))

    top = sorted(failedTries, key =failedTries.get, reverse = True )
    for f in top:
        if int(failedTries[f]) >= int(triesPostgresql):
            ips.add(f[0])
        else:
            break

def analyzeMysqlLogs(log_file):
    global lines
    logs = []
    global error_lines 
    triesPostgresql = 20

    global failedTries_mysql
    global error_logs 
    connections = []

    for line in log_file.readlines():
        lines = lines +1
        date = re.search(r'^(\d{6}.{1,2}\d{1,2}:\d{2}).*',line)
        if date is not None: last_date = date.group(1)
        if re.match(".*(Access|Connect).*denied.*password:", line) is not None:
            badIP = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
            if badIP  is not None:
                failedTries_mysql[(badIP.group(),last_date)] = failedTries_mysql.get((badIP.group(),last_date) , 0) + 1


    top = sorted(failedTries_mysql, key =failedTries_mysql.get, reverse = True )
    for f in top:
        if int(failedTries_mysql[f]) >= int(triesPostgresql):
            ips.add(f[0])
        else:
            break





#Analyze each line of the php log to find the errors
def analyzePhpLogs(log_file):

    global error_fatal
    global error_parse
    global error_warning
    global error_notice
    global error_deprecated
    global lines

    for line in log_file.readlines():
        lines += 1
        if re.search("error",line) is not None:
            err = re.search('PHP ([a-zA-Z]+)( [a-zA-Z]+)?', line)
            if err is not None:
                c_error = err.group(0)
                if re.search("Fatal", c_error):
                    error_fatal += 1
                if re.search("Parse", c_error):
                	error_parse += 1
                if re.search("Warning", c_error):
                	error_warning += 1
                if re.search("Notice", c_error):
                		error_notice += 1
                if re.search("Deprecated", c_error):
                	error_deprecated += 1

                date = re.sub(r'\.[0-9]+ ',' ',' '.join(line.split()[0:5]).strip("]").strip("["))
                desc =re.search(r'(PHP ([a-zA-Z]+)( [a-zA-Z]+)?:  )(.+)( in .+)',line).group(4)
                file_ref = re.search(r'( in )(.+)',line).group(2)

                php_obj = phpLog(c_error, '', desc, date, file_ref)

                detected_php_info.append(php_obj)

#Opens the log files depending on the service and the rotation configurations
def openLogs(log_type, logs, attack_rules, rot_conf):
    for log in logs:
        print color.Cyan+"\t"+log+color.Color_off
        readLog(log_type, log, attack_rules)
        if rot_conf['rotated']:
            rot_logs = getRotatedLogs(log, rot_conf['rot_ext'], rot_conf['rot_max'], 1, []) #Gets a list of the existing rotated logs
            for r_log in rot_logs:
                print color.Cyan+"\t"+r_log+color.Color_off
                readLog(log_type, r_log, attack_rules, rot_conf['compressed'])

#make graphs
def makeGraphs(values,labels,values1,labels1,values2,labels2,name,name2,name3,service):
    fig = {
      "data": [
        {
          "values": values,
          "labels": labels,
          "domain": {"x": [0, .33]},
          "name": name,
          "hoverinfo":"label+percent+name+value",
          "type": "pie"
        },
        {
          "values": values1,
          "labels": labels1,
          "domain": {"x": [.34, .66]},
          "name": name2,
          "hoverinfo":"label+percent+name+value",
          "type": "pie"
        },     
        {
          "values": values2,
          "labels": labels2,
          "text":"CO2",
          "textposition":"inside",
          "domain": {"x": [.67, 1]},
          "name": name3,
          "hoverinfo":"label+percent+name+value",
          "type": "pie"
        }],
      "layout": {
            "title":"Log AnalyCERT v2.0 Web Report for " + service,
            "annotations": [
                {
                    "font": {
                        "size": 20
                    },
                    "showarrow": False,
                    "text": name,
                    "x": 0.14,
                    "y": 1.0
                },
                {
                    "font": {
                        "size": 20
                    },
                    "showarrow": False,
                    "text": name2,
                    "x": 0.50,
                    "y": 1
                },
                {
                    "font": {
                        "size": 20
                    },
                    "showarrow": False,
                    "text": name3,
                    "x": 0.87,
                    "y": 1
                }
            ]
        }
    }
    plotly.offline.plot(fig, filename='report_'+service+'.html', auto_open=False)
    print color.Green + '\treport_'+service+'.html has been created.' + color.Color_off



#Reports the results that hve been found until the selected point
def reportResults(service, attacks_conf, output, graph):
    global detected_attacks
    global detected_php_info
    global lines
    global ips
    labels = []
    values = []
    labels1 = []
    values1 = []
    labels2 = []
    values2 = []
    countries = {}

    with open(output, 'a') as out, open(output+'.ev','a') as evd:
        out.write('\n\n%s%sReport for %s\n%s\n\n' % ('+-'*50+'\n', '\t'*4, service, '+-'*50))
        out.write('\nStart time: %s\n' % ('\t'+str(start_time)))
        out.write('End time: %s\n' % ('\t'+str(datetime.utcnow())))
        out.write('Events parsed: %s\n' % ('\t'+str(lines)))
        if service == 'apache_log' or service == 'nginx_log': out.write('Attacks detected: %s\n\n' % str(len(detected_attacks)))
        evd.write('\n\n%s%sReport for %s\n%s\n\n' % ('+-'*50+'\n', '\t'*4, service, '+-'*50))
        evd.write('\nStart time: %s\n' % ('\t'+str(start_time)))
        evd.write('End time: %s\n' % ('\t'+str(datetime.utcnow())))
        evd.write('Events parsed: %s\n' % ('\t'+str(lines)))
        if service == 'php':
            evd.write('_'*50+'\n\nPHP Errors:\t\tDate:\t\t\t\tFile:\t\t\t\t\tDescription:\n')
            for l in detected_php_info:
                evd.write('%s %s %s %s\n' % (l.c_error,'     \t'+l.date,'\t'+l.file_ref ,'\t'+l.desc))
            out.write('_'*50+'\n\n')
            out.write('Fatal Error:%s \nWarnings: %s\nNotices: %s\nParse Errors: %s\nDeprecated Functions: %s\n' % ('\t\t'+str(error_fatal),'\t\t'+str(error_warning),'\t\t'+str(error_notice),'\t\t'+str(error_parse),'\t'+str(error_deprecated)))

        if service == 'mail':
            out.write('_'*100+'\n\nGeneral information:\n\n')
            out.write("\tConnections: %s\n" % ('\t'+str(count_connections)))
            out.write("\tSent mails: %s\n" % ('\t'+str(count_send)))
            out.write("\tReceived mails: %s\n" % (str(count_received)))
            out.write("\tRejected mails: %s\n" % (str(count_rejected)))

            if graph is True:
                labels = ['Sent mails','Received mails','Rejected mails']
                values = [count_send,count_received,count_rejected]
            out.write("\tFatal error: %s\n" % ('\t'+str(len(fatal_mail))))
            out.write("\tWarnings: %s\n" % ('\t'+str(len(warnings_mail))))
            out.write("\tErrors: %s\n" % ('\t'+str(len(error_mail))))
            out.write("\tPanic: %s\n" % ('\t\t'+str(len(panic_mail))))

            out.write('_'*100+'\n\nRecipients:\n\n')
            top = sorted(dest_dict, key =dest_dict.get, reverse = True )
            for f in top: 
                out.write("\tMail: %-35s Times: %s\n" % (f,str(dest_dict[f])))
                if graph is True:
                    labels1.append(f)
                    values1.append(dest_dict[f])                
            out.write('_'*100+'\n\nSenders:\n\n')
            top = sorted(senders_dict, key =senders_dict.get, reverse = True )
            for f in top: 
                out.write("\tMail: %-35s Times: %s\n" % (f,str(senders_dict[f])))
                if graph is True:
                    labels2.append(f)
                    values2.append(senders_dict[f])   
            out.write('_'*100+'\n\nRejected:\n\n')
            top = sorted(rejected_dict, key =rejected_dict.get, reverse = True )
            for f in top: out.write("\tMail: %-35s Times: %s\n" % (f,str(rejected_dict[f])))
            out.write('_'*100+'\n\nConnections:\n\n')
            top = sorted(ip_dict, key =ip_dict.get, reverse = True )
            for f in top: out.write("\tIP: %s Times: %s\n" % (f+'\t',str(ip_dict[f])))

            # Mail ERRORS to de evidencE report
            evd.write('_'*100+'\n\nPanic:\n\n')
            for e in panic_mail: evd.write('%s' % e) 
            evd.write('_'*100+'\n\nFatal:\n\n')
            for e in fatal_mail: evd.write('%s' % e)
            evd.write('_'*100+'\n\nErrors:\n\n')
            for e in error_mail: evd.write('%s' % e) 
            evd.write('_'*100+'\n\nWarnings:\n\n')
            for e in warnings_mail: evd.write('%s' % e)

            #The attacks will be graphed if the option is enabled.
            if graph is True:
                makeGraphs(values,labels,values1,labels1,values2,labels2,'Mails Information', 'Top Senders', 'Top Recipients',service) 


        #If the service selected is postgresql will create the report with the information found
        if service == 'postgresql':
            out.write('_'*50+'\nFailed Authentication Tries\n\n')
            top = sorted(failedTries, key =failedTries.get, reverse = True )
            for f in top[:10]:
                out.write('\tIP: %s Times: %s User: %s Data Base: %s Date: %s %s\n' % (f[0]+'\t',str(failedTries[f])+'\t',f[3],f[4],f[1],f[2]))
            out.write('_'*50+'\nErrors\n\n')
            top = sorted(error_logs, key =error_logs.get, reverse = True )
            for f in top[:10]:
                out.write('\tTimes: %s Data Base: %s Error: %s\n' % (str(error_logs[f])+'\t',f[0]+'\t',f[1]))
            
            evd.write('_'*50+'\nErrors\n\n')
            for error in error_lines: 
                evd.write('%s\n' % (error))





        #If the service selected is postgresql will create the report with the information found
        if service == 'ftp':    
            out.write('_'*100+'\n\nGeneral information:\n\n')
            out.write("\tDownloaded files: %s\n" % ('\t'+str(len(downloaded_ftp))))
            out.write("\tUploaded files: %s\n" % ('\t'+str(len(uploaded_ftp))))
            out.write("\tFailed logins: %s\n" % ('   \t'+str(login_fallido)))


            out.write('_'*50+'\n\nTop 10 Downloaded Files\n\n')
            top = sorted(downloaded_files, key =downloaded_files.get, reverse = True )
            for f in top[:10]:
                out.write('\tFile: %-40s Times: %s\n' % (f, str(downloaded_files[f])))
                if graph is True:
                    labels.append(f)
                    values.append(downloaded_files[f])
            out.write('_'*50+'\n\nTop 10 failed Requests by IP per minute\n\n')
            top = sorted(failedTries_ftp, key =failedTries_ftp.get, reverse = True )
            for x in top[:10]:
                out.write("\tIP: %s Retries: %s Date: %s Country: %s\n" % (x[1]+'    \t', str(failedTries_ftp[x])+'\t', x[0]+'\t', getCountry(x[1]) ))
#            for x in top:
#                if failedTries[x] > sshTries:
#                        ips.add(x[0])
            top = sorted(failure_ips_ftp, key =failure_ips_ftp.get, reverse = True )
            out.write('_'*50+'\n\nTop 10 failed Requests by IP\n\n')
            for x in top[:10]:
                out.write('\tIP: %s Retries: %s  Country: %s\n' % (x+'    \t',str(failure_ips_ftp[x])+'\t',getCountry(x)))
                countries[(getCountry(x))] = countries.get((getCountry(x)) , 0) + failure_ips_ftp[x]
                if graph is True:
                    labels2.append(x)
                    values2.append(failure_ips_ftp[x])


            top = sorted(failure_usr_ftp, key =failure_usr_ftp.get, reverse = True )
            out.write('_'*50+'\n\nTop 10 failed users\n\n')
            for x in top[:10]:
                out.write("\tUser: %-15s Retries: %s\n" % (x, failure_usr_ftp[x]))

            evd.write('_'*50+'\nDownloaded Files:\n\n')
            for l in downloaded_ftp: 
                evd.write('%s' % (l))

            evd.write('_'*50+'\nUploaded Files:\n\n')
            for l in uploaded_ftp: 
                evd.write('%s' % (l))

            #The attacks will be graphed if the option is enabled.
            if graph is True:
                for x in countries:
                    labels1.append(x)
                    values1.append(countries[x])
                makeGraphs(values,labels,values1,labels1,values2,labels2,'Top Downloaded Files', 'Top Countries', 'IP attackers',service) 


        #If the service selected is postgresql will create the report with the information found
        if service == 'ssh':               
            out.write("_"*40+"\nTotal failed logins attempts: %s\n" % str(failed_attempts))

            top = sorted(failure_IPS, key =failure_IPS.get, reverse = True )

            out.write("\nTop 10 failed Requests by IP\n\n")
            for x in top[:10]:
                out.write('\tIP: %s Retries: %s  Country: %s\n' % (x+'    \t',str(failure_IPS[x])+'\t',getCountry(x)))
                countries[(getCountry(x))] = countries.get((getCountry(x)) , 0) + failure_IPS[x]
                if graph is True:
                    labels2.append(x)
                    values2.append(failure_IPS[x])

            top = sorted(failure_USRS, key =failure_USRS.get, reverse = True )
            out.write("\nTop 10 failed users\n\n")
            for x in top[:10]:
                out.write("\tUser: %s Retries: %s\n" % (x+'\t', failure_USRS[x]))
                if graph is True:
                    labels.append(x)
                    values.append(failure_USRS[x])
            top = sorted(failedTries, key =failedTries.get, reverse = True )
            out.write("\nTop 10 failed Requests by IP per minute\n\n")
            for x in top[:10]:
                out.write("\tIP: %s Retries: %s Date: %s Country: %s\n" % (x[0]+'    \t', str(failedTries[x])+'\t', x[1]+'\t', getCountry(x[0]) ))
            for x in top:
                if failedTries[x] > sshTries:
                        ips.add(x[0])    

            #The attacks will be graphed if the option is enabled.
            if graph is True:
                for x in countries:
                    labels1.append(x)
                    values1.append(countries[x])
                makeGraphs(values,labels,values1,labels1,values2,labels2,'Failed Login Users', 'Countries', 'IP attackers',service) 



        #If the service selected is postgresql will create the report with the information found
        if service == 'mysql':
            out.write('_'*50+'\nFailed Authentication Tries\n\n')
            top = sorted(failedTries_mysql, key =failedTries_mysql.get, reverse = True )
            for f in top[:10]:
                out.write('\tIP: %s Times: %s Date: %s \n' % (f[0]+'\t',str(failedTries_mysql[f])+'\t',f[1]))
            out.write('_'*50+'\nErrors\n\n')

#            top = sorted(error_logs, key =error_logs.get, reverse = True )
#            for f in top[:10]:
#                out.write('\tTimes: %s Data Base: %s Error: %s\n' % (str(error_logs[f])+'\t',f[0]+'\t',f[1]))
#            
#            evd.write('_'*50+'\nErrors\n\n')
#            for error in error_lines: 
#                evd.write('%s\n' % (error))


        #If the service selected is apache or nginx will create the report with
        #the attacks found.
        if service == 'apache' or service == 'nginx':
            evd.write('Attacks detected: %s\n\n' % str(len(detected_attacks)))
            for a in attacks_conf:
                attack_filter = filter(lambda x: x.attack == a, detected_attacks)
                out.write('_'*50+'\n\n')
                out.write('%s\n' % ( a_dict[a]))
                out.write('Total attacks:\t%s\n' % str(len(attack_filter)))
                evd.write('_'*50+'\n\n')
                evd.write('%s\n' % ( a_dict[a]))
                evd.write('Total attacks:\t%s\n' % str(len(attack_filter)))

                #The attacks will be graphed if the option is enabled.
                if graph is True:
                    labels.append(a_dict[a])
                    values.append(len(attack_filter))

                #Gets the top of IPs and response codes
                ip_times = {}
                code_times = {}
                for af in attack_filter:
                    evd.write(str(af))
                    ips.add(af.ip) #Adds the ips to a set so finally a file with those IPs can be written
                    if af.ip in ip_times.keys(): ip_times[af.ip] += 1
                    else: ip_times[af.ip] = 1

                    if af.code in code_times.keys(): code_times[af.code] += 1
                    else: code_times[af.code] = 1

                top_ips = sorted(ip_times, key =ip_times.get, reverse = True )
                top_codes = sorted(code_times, key=code_times.get, reverse = True)


                for ip in ip_times:
                    ip_attacks_total[(ip)] = ip_attacks_total.get((ip) , 0) + ip_times[ip]                    

                out.write('\n\tTop 10 attacker IPv4 addresses:\n')
                for ip in top_ips[:10]:
                    out.write('\t\t%s:\t%s\n' % (ip, ip_times[ip]))


                out.write('\n\tTop 10 response codes:\n')
                for code in top_codes[:10]:
                    out.write('\t\t%s:\t%s\n' % (code, code_times[code]))

            top = sorted(bruteForce, key =bruteForce.get, reverse = True )
            out.write('_'*50+'\n\n')
            out.write("Requests per minute to the same resource by the same ip\n\n")
            for x in top[:10]:
                out.write('\tCode: %s Times: %s Request: %s\n' % (x[0]+'\t',str(bruteForce[x])+'\t',x[1]))
            top = sorted(crawlers, key =crawlers.get, reverse = True )
            out.write('_'*50+'\n\n')
            out.write("Requests by crawlers\n\n")
            for x in top[:10]:
                out.write('\tTimes: %s Agent: %s\n' % (str(crawlers[x])+'\t',x))

            out.write('_'*50+'\n\n')
            out.write("Top 10 attacker IPv4 addresses total\n\n")
            top = sorted(ip_attacks_total, key =ip_attacks_total.get, reverse = True )
            for ip in top[:10]:
                out.write('\t\t%s:\t%s\t%s\n' % (ip, ip_attacks_total[ip],getCountry(ip)))
                countries[(getCountry(ip))] = countries.get((getCountry(ip)) , 0) + ip_attacks_total[ip]
                if graph is True:
                    labels2.append(ip)
                    values2.append(ip_attacks_total[ip])


            #The attacks will be graphed if the option is enabled.
            if graph is True:
                for x in countries:
                    labels1.append(x)
                    values1.append(countries[x])
                makeGraphs(values,labels,values1,labels1,values2,labels2,'Attacks', 'Countries', 'IP attackers',service) 


    lines = 0
    detected_attacks = []



#Opens the file depending on the selected configuration
def filterAnalysis(opts, logs, rules, rot_conf):
#    installed_services = checkServices(checkDistro())
    services = filter(lambda x: opts[x], ['apache','nginx','postgresql','mysql','ssh','php','ftp','mail'])
    f_attacks = filter(lambda x: opts[x], ['rfi','lfi','sqli','xss','csrf','dt','bf','craw'])
    graph_attacks = []
    attack_rules = {}
    if 'rfi' in f_attacks: attack_rules['rfi'] = rules['rfi_rule']
    if 'lfi' in f_attacks: attack_rules['lfi'] = rules['lfi_rule']
    if 'sqli' in f_attacks: attack_rules['sqli'] = rules['sqli_rule']
    if 'xss' in f_attacks: attack_rules['xss'] = rules['xss_rule']
    if 'csrf' in f_attacks: attack_rules['csrf'] = rules['csrf_rule']
    if 'dt' in f_attacks: attack_rules['dt'] = rules['dt_rule']
    if 'craw' in f_attacks: attack_rules['craw'] = rules['crawler_rule']
    if 'bf' in f_attacks: attack_rules['bf'] = [rules['bf_seconds'], rules['bf_tries']]

    global start_time
    start_time = datetime.utcnow()
    if 'apache' in services:
        print color.Cyan+color.Bold+"\nAnalyzing apache logs"+color.Color_off
        checkLogFiles(logs['apache_log']) #Checks if configured log files actually exist
        openLogs('apache_log', logs['apache_log'], attack_rules, rot_conf)
        reportResults('apache', f_attacks, opts['output'], opts['graph'])

    if 'nginx' in services:
        print color.Cyan+color.Bold+"\nAnalyzing nginx logs"+color.Color_off
        checkLogFiles(logs['nginx_log'])
        openLogs('nginx_log', logs['nginx_log'], attack_rules, rot_conf)
        reportResults('nginx', f_attacks, opts['output'], opts['graph'])

    if 'postgresql' in services:
        print color.Cyan+color.Bold+"\nAnalyzing postgresql logs"+color.Color_off
        attack_rules = {'bf': [rules['bf_seconds'], rules['bf_tries']]} #If analysing database, will only look for BF attacks
        checkLogFiles(logs['postgresql_log'])
        openLogs('postgresql_log', logs['postgresql_log'], attack_rules, rot_conf)
        reportResults('postgresql', f_attacks, opts['output'], opts['graph'])

    if 'mysql' in services:
        print color.Cyan+color.Bold+"\nAnalyzing mysql logs"+color.Color_off
        checkLogFiles(logs['mysql_log'])
        openLogs('mysql_log', logs['mysql_log'], attack_rules, rot_conf)
        reportResults('mysql', f_attacks, opts['output'], opts['graph'])

    if 'ssh' in services:
        print color.Cyan+color.Bold+"\nAnalyzing ssh logs"+color.Color_off
        checkLogFiles(logs['ssh_log'])
        openLogs('ssh_log', logs['ssh_log'], attack_rules, rot_conf)
        reportResults('ssh', f_attacks, opts['output'], opts['graph'])

    if 'php' in services:
        print color.Cyan+color.Bold+"\nAnalyzing php logs"+color.Color_off
        checkLogFiles(logs['php_log'])
        openLogs('php_log', logs['php_log'], attack_rules, rot_conf)
        reportResults('php', f_attacks, opts['output'], opts['graph'])

    if 'ftp' in services:
        print color.Cyan+color.Bold+"\nAnalyzing ftp logs"+color.Color_off
        checkLogFiles(logs['ftp_log'])
        openLogs('ftp_log', logs['ftp_log'], attack_rules, rot_conf)
        reportResults('ftp', f_attacks, opts['output'], opts['graph'])

    if 'mail' in services:
        print color.Cyan+color.Bold+"\nAnalyzing mail logs"+color.Color_off
        checkLogFiles(logs['mail_log'])
        openLogs('mail_log', logs['mail_log'], attack_rules, rot_conf)
        reportResults('mail', f_attacks, opts['output'], opts['graph'])
    print color.Green+'\n'+opts['output']+' has been created'+color.Color_off
    print color.Green+opts['output']+'.ev has been created'+color.Color_off

#Opens a file so the attackes IP addresses can be written in it
def writeIPToFile(output):
    with open(output+'.ips', 'w') as o:
        for ip in ips:
            o.write(ip+'\n')
    print color.Green+output+'.ips has been created'+color.Color_off


#Start point
if __name__ == '__main__':
#    try:
    start_time = datetime.utcnow()
    cmd_opts = addOptions() #Adds the options to use
    checkOptions(cmd_opts) #Validates that all the options are correct
    banner()
    log_conf, exec_conf, rules, rot_conf = readConfigFile(cmd_opts.config) #Get initial configurations from the config file
    exec_conf = setExecConf(exec_conf) #Changes strings/numbers for actual boolean values
    exec_conf = setFinalExecConf(exec_conf, cmd_opts) #Set final execution options depending on config file and command-line options
    setGlobalConf(exec_conf)
    log_conf = setFinalLogConf(log_conf, cmd_opts)
    rot_conf = setFinalRotConf(rot_conf, cmd_opts)
    filterAnalysis(exec_conf, log_conf, rules, rot_conf)
    writeIPToFile(exec_conf['output'])

#    except IOError:
#        printError('Unknown error', True)
