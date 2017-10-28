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
						r_php.fecha = ' '.join(line.split()[0:5]).strip("]").strip("[")
						r_php.fecha = re.sub(r'\.[0-9]+ ',' ',r_php.fecha) 
						r_php.desc =re.search(r'(PHP ([a-zA-Z]+)( [a-zA-Z]+)?:  )(.+)( in .+)',line)
						r_php.archivo = re.search(r'( in )(.+)',line)
						r_php.archivo = r_php.archivo.group(2)

						file_reporte.write(r_php.c_error + "\t"  + r_php.fecha + "   " + r_php.desc.group(4) + "\t" + r_php.archivo + "\n")
						#print r_php.c_error + "\t"  + r_php.fecha + "\t" + r_php.desc.group(4) + "\t" + r_php.archivo 


		file_reporte.close

analyzePhpLogs(filesLogPhp)
