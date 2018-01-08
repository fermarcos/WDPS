#!/usr/bin/python

#########################################################
###              WDPS PROJECT UNAM-CERT               ###
###    COORDINACION DE SEGURIDAD DE LA INFORMACION    ###
###     Plan de becarios en Seguridad Informatica     ###
###     -----------------------------------------     ###
###           Diana Laura Arrieta Jimenez             ###
###                                                   ###
#########################################################

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
#
#########################################################
######      POLITICA BASE - ModSecurity            ######
#########################################################

#=======================================================#

from optparse import OptionParser
import subprocess, os

parser = OptionParser(usage="%prog[options]")
parser.add_option('-f','--file', dest='file', \
help = 'indicar el nombre el archivo con el id de las reglas. Ejemplo: -f politica/p_wordpress', \
metavar='FILE', default='politica/p_default', \
type = 'string')

(option, args) = parser.parse_args()

f = open(option.file,'r')
FNULL = open(os.devnull,'w')
for line in f:
	i = 0
	id = line.split(':')[0]
	arguments = "grep -lr id:" + id + " /usr/share/modsecurity-crs/* "
	archivo_conf = subprocess.call(arguments,shell=True,stdout=FNULL)
	arguments2 = "grep -l id:\\'" + id + " /etc/modsecurity/modsecurity.conf"
	archivo_conf2 = subprocess.call(arguments2,shell=True,stdout=FNULL)	
	if archivo_conf == 0:
		archivo_conf = str(subprocess.check_output(arguments,shell=True))
		while i<10:
			arguments = "grep -n -B "+ str(i) + " id:"+ id + " " + archivo_conf[:-1] + " | grep SecRule"
			result = subprocess.call(arguments,shell=True,stdout=FNULL)
			if result == 0:
				result = str(subprocess.check_output(arguments, shell=True)).split('-')[0]
				sed = ' '+str(result)+' s/^/\#/g'
				subprocess.call(["sed","-i","-e", sed , archivo_conf[:-1]])
				break
			else:
				i+=1
	if archivo_conf2 == 0:
		while i<10:
			arguments2 = "grep -n -B "+ str(i) + " id:\\'"+ id + " /etc/modsecurity/modsecurity.conf | grep SecRule"
			result = subprocess.call(arguments2,shell=True,stdout=FNULL)
			if result == 0:
				result = str(subprocess.check_output(arguments2, shell=True)).split('-')[0]
				sed = ' '+str(result)+' s/^/\#/g'
				subprocess.call(["sed","-i","-e", sed , "/etc/modsecurity/modsecurity.conf"])
				break
			else:
				i+=1
f.close()
FNULL.close()
