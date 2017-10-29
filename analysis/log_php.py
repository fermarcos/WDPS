#!/usr/bin/env python
#***** Modulo de analisis de errores de PHP
#***** Elaborado por  Diana L. Arrieta Jimenez


import re
import sys
import os

filesLogPhp = []
filesLogPhp.append('error.log')
#filesLogPhp.append('moodle-respaldo-error.log')


class prueba(object):
	def _init_(self):
		self.c_error
		self.ip_client
		self.desc
		self.fecha
		self.archivo

r_php = prueba()

def analyzePhpLogs(logs):

	for l in logs:
		error_fatal = 0
		error_parse = 0
		error_warning = 0
		error_notice = 0
		error_deprecated = 0

		file_reporte = open ("reporte-"+l+".txt","w")

		print "\nAnalizando error y funciones obsoletas PHP para " + l 
		with open(l) as f:
			file_reporte.write("-------- REPORTE PHP ---------\n\n\n")
			file_reporte.write("ERROR           Fecha                      DESCRIPCION \n\n" )
			lines = f.readlines()
			for line in lines:
				if re.search("error",line) is not None:
					err = re.search('PHP ([a-zA-Z]+)( [a-zA-Z]+)?', line)
					if err is not None:
						r_php.c_error = err.group(0)
						if re.search("Fatal", r_php.c_error):
							error_fatal += 1
						if re.search("Parse", r_php.c_error):
                					error_parse += 1
						if re.search("Warning", r_php.c_error):
                					error_warning += 1
						if re.search("Notice", r_php.c_error):
               						error_notice += 1
						if re.search("Deprecated", r_php.c_error):
                					error_deprecated += 1
						r_php.fecha = re.sub(r'\.[0-9]+ ',' ',' '.join(line.split()[0:5]).strip("]").strip("[")) 
						r_php.desc =re.search(r'(PHP ([a-zA-Z]+)( [a-zA-Z]+)?:  )(.+)( in .+)',line).group(4)
						r_php.archivo = re.search(r'( in )(.+)',line).group(2)

						file_reporte.write(r_php.c_error + "\t"  + r_php.fecha + "   " + r_php.desc + "\t" + r_php.archivo + "\n")
						#print r_php.c_error + "\t"  + r_php.fecha + "\t" + r_php.desc.group(4) + "\t" + r_php.archivo 
		print "\nError faltal: " + str(error_fatal) + "\nWarning: "  + str(error_warning) + "\nNotice: " + str(error_notice)  + "\nParse error: "+ str(error_parse) +"\nFunction deprecated: " + str(error_deprecated)


		file_reporte.close

analyzePhpLogs(filesLogPhp)
