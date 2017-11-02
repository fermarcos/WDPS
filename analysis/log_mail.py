#!/usr/bin/env python
#***** Modulo de analisis de errores de mail
#***** Elaborado por  Diana L. Arrieta Jimenez


import re
import sys
import os,string

filesLogMail = []
filesLogMail.append('maillog')
#filesLogPhp.append('')


#class error(object):
#	def _init_(self):
#		self.fatal
#		self.warning

#r_mail = prueba()

def analyzeMailLogs(logs):

	num = 0
	e_fatal = []
	e_warning = []
	e_error = []
	e_panic = []
	destinatarios = []
	remitentes = []
	remitentes_rej = []
	ip_connections = []

	count_mail = 0
	count_e_fatal = 0
	count_e_warning = 0
	count_e_error = 0
	count_e_panic = 0 
	count_send = 0
	count_received = 0
	count_rejected = 0
	count_inSysStorage = 0
	count_connections = 0

	for l in logs:
		with open(l) as f:
			num += 1
			reporte = open("reporte_mail"+str(num)+".txt","w")

			lines = f.readlines()
			for line in lines:
				if re.search("postfix",line):
					if re.search("fatal: ",line):
						e_fatal.append(re.search("(fatal: )(.+)",line).group(2))
						count_e_fatal += 1
					if re.search("warning",line):
						e_warning.append(re.search("(warning: )(.+)",line).group(2))
						count_e_warning += 1
					if re.search("error: ",line):
						e_error.append(re.search("(error: )(.+)",line).group(2))
						count_e_error += 1
					if re.search("panic: ",line):
						e_panic.append(re.search("(panic: )(.+)",line).group(2))
						count_e_panic += 1
					if re.search("smtpd.+connect from",line):
						ip_connections.append(re.search("(connect from.+\[)(.+)(\])",line).group(2))
						count_connections += 1
					if re.search("smtp.+sent",line):
						destinatarios.append(re.search("(to=<)(.+)(>,)",line).group(2))
						count_send += 1
						#print re.search("(to=<)(.+)(>,)",line).group(2)
					if re.search("relay=local.+status=sent",line):
						count_received += 1
					if re.search("qmgr.+from=<",line):
						remitentes.append(re.search("(from=<)(.+)(>,)",line).group(2))						
					if re.search("reject",line):
						count_rejected += 1
						if re.search("from=<",line) is not None:
							remitentes_rej.append(re.search("(from=<)(.+)(> to=)",line).group(2))
					if re.search("Insufficiented system storage",line):
						count_inSysStorage += 1


			destinatarios = set(destinatarios)
			remitentes = set(remitentes)
			remitentes_rej = set(remitentes_rej)
			ip_connections = set(ip_connections)
#			Errores 
#			print "\n".join(e_fatal)
#			print "\n".join(e_warning)
#			print "\n".join(e_error)
#			print "\n".join(e_panic)
#			print "\n".join(destinatarios)
#			print "\n".join(remitentes)

			reporte.write("\nTotal de conexiones: " + str(count_connections))			
			reporte.write("\nTotal de correos enviados: " + str(count_send))
			reporte.write("\nTotal de correos recibidos: " + str(count_received))
		 	reporte.write("\nTotal de correos rechazados: " + str(count_rejected))
			reporte.write("\nTotal de Error Fatal " + str(count_e_fatal))
			reporte.write("\nTotal Warning: " + str(count_e_warning))
			reporte.write("\nTotal de  Error: " + str(count_e_error))
			reporte.write("\nTotal de Panic: " + str(count_e_panic))

			reporte.write("\n\n-------------------\n")
			reporte.write(" ** IP conectadas **\n\n")
			reporte.write("\n".join(ip_connections))
			reporte.write("\n\n-------------------\n")
			reporte.write(" ** Destinatarios **\n\n")
			reporte.write("\n".join(destinatarios))
                        reporte.write("\n\n\n-------------------\n")
			reporte.write(" ** Remitentes **\n\n")
                        reporte.write("\n".join(remitentes))
                        reporte.write("\n\n\n-------------------\n")
			reporte.write(" ** Remitentes Rechazados**\n\n")
                        reporte.write("\n".join(remitentes_rej))
                        reporte.write("\n\n\n-------------------\n")			
			reporte.write("\n\n Error Fatal\n\n")
                        reporte.write("\n".join(e_fatal))
			reporte.write("\n\n Warning\n\n")
                        reporte.write("\n".join(e_warning))
			reporte.write("\n\n Error\n\n")
                        reporte.write("\n".join(e_error))
			reporte.write("\n Panic\n\n")
                        reporte.write("\n".join(e_panic))

			reporte.close
analyzeMailLogs(filesLogMail)
