#!/usr/bin/python
# -*- coding: utf-8 -*-
#Log AnalyCERT v2.0
#Castro Rendón Virgilio
#Parra Arroyo Fernando Marcos
#Arrieta Jiménez Diana Laura

import subprocess
import sys
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

bruteForce = dict()
crawlers = dict()
ips = set()
start_time = ''
lines = 0
detected_attacks = []
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

#Class to manage each record in the log file. If it's consider an attack, will saved using this class.
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
    sys.stderr.write('Error:\t%s\n' % msg)
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
    parser.add_option('--rot-max', dest='rot_max', default=None, help='Max number of rotated files to analyze.')
    parser.add_option('--rot-compressed', dest='compressed', default=None, action="store_true", help='If indicated, means that rotated logs are compressed.')
    parser.add_option('-g','--graph', dest='graph', default=None, action="store_true", help='If indicated, the results will be graphed')
    parser.add_option('-v','--verbose', dest='verbose', default=None, action="store_true", help='If indicated, the programm will show the progress in standard output.')
    parser.add_option('-o','--output', dest='output', default=None,  help='Indicates the name of the report file.')
    parser.add_option('-r','--log-rotated', dest='rotated', default=None, action="store_true", help='If indicated, will look for rotated logs.')
    parser.add_option('-c','--config-file', dest='config', default=None, help='Configuration file for the script.')
    parser.add_option('-a','--attack-type', dest='attacks', default=None, help='Attack types to detect. [lfi,rfi,sqli,xss,csrf,dt,bf,craw]')
    parser.add_option('-s','--services', dest='services', default=None, help='Services to analyze. [apache,nginx,postgresql,mysql,ssh]')
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
            if service not in ['apache','nginx','postgresql','mysql','ssh']:
                printError('Could not understand the service %s. Try using: apache, nginx, postgresql, mysql or ssh' % service, True)



#Reads and parses the configuration file
def readConfigFile(config):
    #These are the dictionaries used to store the info from the config file
    log_conf = {'apache_log':[], 'nginx_log':[], 'postgresql_log':[], 'mysql_log':[], 'ssh_log':[]}
    rules = {'rfi_rule':[], 'lfi_rule':[], 'sqli_rule':[], 'xss_rule':[], 'csrf_rule':[], 'dt_rule':[], 'crawler_rule':[], 'bf_seconds':'', 'bf_tries':''}
    exec_conf = {'rfi': '', 'lfi':'', 'sqli':'', 'xss':'', 'csrf':'', 'dt':'', 'bf':'', 'craw':'', 'apache':'', 'nginx':'', 'mysql':'', 'ssh':'', 'postgresql':'', 'graph':'', 'verbose':'', 'output':''}
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

    available_services = ['apache','nginx','postgresql','mysql','ssh']
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
        print "Analyzing SSH"
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
                        #print "BAIDUUUUU"
                        #print unquoted
                        return attack_obj



#Defines all the fields that are used in the log file
def parseLine(log_type, line, attack_rules):
    global lines
    lines += 1
    log_regex = { 'apache_log':r'(?P<ip>^(([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.){3}([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5]))[\s\-]+\[(?P<date>[^\s]+)[^\"]+\"(?P<method>[^\s]+)\s+(?P<request>[^\s]+)\s+[^\"]+\"\s(?P<code>\w+)[^\"]+\"(?P<name>[^\"]+)\"\s+\"(?P<agent>[^\"]+)',
            'nginx_log':r'(?P<ip>^(([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.){3}([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5]))[\s\-]+\[(?P<date>[^\s]+)[^\"]+\"(?P<method>[^\s]+)\s+(?P<request>[^\s]+)\s+[^\"]+\"\s(?P<code>\w+)[^\"]+\"(?P<name>[^\"]+)\"\s+\"(?P<agent>[^\"]+)',
            'postgresql_log':r'^(?P<date>[^\s]+\s[^\s]+)[^\[]+\[[^\s]+\s(?P<request>[^\s]+)\s(?P<code>[^:]+):[^\"]+\"(?P<ip>(([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.){3}([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])).+$',
            'ssh_log':r'(?P<date>^[A-Za-z]{3} \d{2} \d{2}:\d{2}:\d{2}) (?P<code>[a-z]+) (?P<request>.*)'
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
            for l in i.readlines():
                parseLine(log_type, l, attack_rules)
    else:
        with open(log, 'r') as i:
            for l in i.readlines():
                parseLine(log_type, l, attack_rules)

#Opens the log files depending on the service and the rotation configurations
def openLogs(log_type, logs, attack_rules, rot_conf):
    for log in logs:
        print "Analyzing "+log
        readLog(log_type, log, attack_rules)
        if rot_conf['rotated']:
            rot_logs = getRotatedLogs(log, rot_conf['rot_ext'], rot_conf['rot_max'], 1, []) #Gets a list of the existing rotated logs
            for r_log in rot_logs:
                print "Analyzing "+r_log
                readLog(log_type, r_log, attack_rules, rot_conf['compressed'])


#Reports the results that hve been found until the selected point
def reportResults(service, attacks_conf, output, graph):
    global detected_attacks
    global lines
    global ips
    labels = []
    values = []
    #for p in detected_attacks: print p #debug
    with open(output, 'a') as out, open(output+'.ev','a') as evd:
        out.write('\n\n%s%sReport for %s\n%s\n\n' % ('+-'*50+'\n', '\t'*4, service, '+-'*50))
        out.write('\nStart time: %s\n' % start_time)
        out.write('End time: %s\n' % datetime.utcnow())
        out.write('Events parsed: %s\n' % lines)
        out.write('Attacks detected: %s\n\n' % str(len(detected_attacks)))
        evd.write('\n\n%s%sReport for %s\n%s\n\n' % ('+-'*50+'\n', '\t'*4, service, '+-'*50))
        evd.write('\nStart time: %s\n' % start_time)
        evd.write('End time: %s\n' % datetime.utcnow())
        evd.write('Events parsed: %s\n' % lines)
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

            out.write('\n\tTop 10 attacker IPv4 addresses:\n')
            for ip in top_ips[:10]:
                out.write('\t\t%s:\t%s\n' % (ip, ip_times[ip]))
            out.write('\n\tTop 10 response codes:\n')
            for code in top_codes[:10]:
                out.write('\t\t%s:\t%s\n' % (code, code_times[code]))

    lines = 0
    detected_attacks = []

    #The attacks will be graphed if the option is enabled.
    if graph is True:
        trace = go.Pie(labels=labels, values=values)
        plotly.offline.plot([trace], filename='attacks.html')



#Opens the file depending on the selected configuration
def filterAnalysis(opts, logs, rules, rot_conf):
#    installed_services = checkServices(checkDistro())
    services = filter(lambda x: opts[x], ['apache','nginx','postgresql','mysql','ssh'])
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
        checkLogFiles(logs['apache_log']) #Checks if configured log files actually exist
        openLogs('apache_log', logs['apache_log'], attack_rules, rot_conf)
        reportResults('apache', f_attacks, opts['output'], opts['graph'])

    if 'nginx' in services:
        checkLogFiles(logs['nginx_log'])
        openLogs('nginx_log', logs['nginx_log'], attack_rules, rot_conf)
        reportResults('nginx', f_attacks, opts['output'], opts['graph'])

    if 'postgresql' in services:
        attack_rules = {'bf': [rules['bf_seconds'], rules['bf_tries']]} #If analysing database, will only look for BF attacks
        checkLogFiles(logs['postgresql_log'])
        openLogs('postgresql_log', logs['postgresql_log'], attack_rules, rot_conf)
        reportResults('posgresql', f_attacks, opts['output'], opts['graph'])

    if 'mysql' in services:
        pass
#        checkLogFiles(logs['mysql_log'])
#        openLogs('mysql', logs['mysql_log'], attack_rules, rot_conf)
#        reportResults('mysql', f_attacks, opts['output'], opts['graph'])

    if 'ssh' in services:
        checkLogFiles(logs['ssh_log'])
        openLogs('ssh_log', logs['ssh_log'], attack_rules, rot_conf)
#        reportResults('mysql', f_attacks, opts['output'], opts['graph'])


#Opens a file so the attackes IP addresses can be written in it
def writeIPToFile(output):
    with open(output+'.ips', 'w') as o:
        for ip in ips:
            o.write(ip+'\n')


#Start point
if __name__ == '__main__':
#    try:
    start_time = datetime.utcnow()
    cmd_opts = addOptions() #Adds the options to use
    checkOptions(cmd_opts) #Validates that all the options are correct
    log_conf, exec_conf, rules, rot_conf = readConfigFile(cmd_opts.config) #Get initial configurations from the config file
    exec_conf = setExecConf(exec_conf) #Changes strings/numbers for actual boolean values
    exec_conf = setFinalExecConf(exec_conf, cmd_opts) #Set final execution options depending on config file and command-line options
    setGlobalConf(exec_conf)
    log_conf = setFinalLogConf(log_conf, cmd_opts)
    rot_conf = setFinalRotConf(rot_conf, cmd_opts)
    filterAnalysis(exec_conf, log_conf, rules, rot_conf)
    writeIPToFile(exec_conf['output'])
#    print bruteForce
    top = sorted(bruteForce, key =bruteForce.get, reverse = True )
    print "\nRequests per minute to the same resource by the same ip\n"
    for x in top[:10]:
        print "\tCode: "+x[0]+ "   \tTimes: "+str(bruteForce[x])+"  \tRequest: "+x[1]

    top = sorted(crawlers, key =crawlers.get, reverse = True )
    print "\nRequests by crawlers\n"
    for x in top[:10]:
        print "\tTimes: "+str(crawlers[x])+"  \tAgent: "+x
#    except IOError:
#        printError('Unknown error', True)
