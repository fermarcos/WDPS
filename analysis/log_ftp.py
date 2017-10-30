#!/usr/bin/env python
#***** Modulo de analisis de bitacoras de FTP
#***** Elaborado por  Diana L. Arrieta Jimenez


import re
import sys
import subprocess


filesLogPhp = []
filesLogPhp.append('vsftpd.log')
#filesLogPhp.append('moodle-respaldo-error.log')


class prueba(object):
	def _init_(self):
		self.c_estado
		self.ip_client
		self.usuario
		self.fecha
		self.archivo

r_ftp = prueba()

def analyzeFtpLogs(logs):
	i=0
	for l in logs:


		cliente_IP = []
		linea_ftp = []
		upload = 0
		download  = 0
		login_exitoso = 0
		login_fallido = 0
		failed = []

		i=i+1
		file_reporte = open ("reporte-" + str(i) + ".txt","w")
		file_failed = open ("failed.txt","w")
		print "\nAnalizando error y funciones obsoletas FTP para " + l 
		with open(l) as f:
			lines = f.readlines()
			for line in lines:
				r_ftp.estado = ' '.join(line.split()[8:10]).strip(":")
				if not re.search ("Client",r_ftp.estado) :

					linea_ftp.append(line)
					cliente_IP.append(re.search(r'(\d{1,3}\.){3}\d{1,3}',line).group(0))
					if re.search("OK UPLOAD",r_ftp.estado):
                                                upload +=  1
                                        if re.search ("OK DOWNLOAD",r_ftp.estado):
                                                download +=  1
					if re.search("OK LOGIN",r_ftp.estado):
                                                login_exitoso +=1
                                        if re.search("FAIL LOGIN",r_ftp.estado):
                                                login_fallido +=  1
						file_failed.write(line)
		file_failed.close


		file_failed = open ("failed.txt")
		proc1=subprocess.Popen(['cut','-d',' ','-f','1-4'],stdin=file_failed,stdout=subprocess.PIPE)
		file_failed.close
		proc2=subprocess.Popen(['cut','-d',':','-f','1,2'],stdin=proc1.stdout,stdout=subprocess.PIPE)
		proc3=subprocess.Popen(['uniq','-c'],stdin=proc2.stdout,stdout=subprocess.PIPE)

		(a,err)=proc3.communicate()

		brute = a.split("\n")
		brute.pop()


		f_bruta = 0
		print "\n -------------------------------- "
		print " ----- Ataques de Fuerza bruta --- \n"
		print " Num.\tFecha \n"
		for b in brute:

			if int(b.split()[0]) > 4: 

				f_bruta += 1
				print b

                print "\n\n -- Ataques ( +5 eventos / minuto): " + str(f_bruta) + "\n\n"


		file_reporte.write("-------- REPORTE FTP ---------\n\n\n")

		cliente_IP =  set(cliente_IP)

		for client in cliente_IP :

			file_reporte.write("\n ----------- DIRECCION IP ORIGEN  -- " + client + "\n\n")
			for line in linea_ftp:
				if re.search(client,line):
					r_ftp.estado = ' '.join(line.split()[8:10]).strip(":")

					r_ftp.archivo = " "


					r_ftp.usuario = (line.split()[7]).strip("[").strip("]")
					r_ftp.fecha = ' '.join(line.split()[0:5])
					if re.search("UPLOAD",r_ftp.estado) or re.search("DOWNLOAD",r_ftp.estado) :
						r_ftp.archivo = line.split(",")[1]

					file_reporte.write(r_ftp.fecha + "\t" + r_ftp.estado + "\t" + r_ftp.usuario + "\t" + r_ftp.archivo + "\n")

		file_reporte.close
	print "+- Archivos subidos: " + str(upload) + "\n+- Archivos descargados: " + str(download) + "\n+- Login exitosos: " + str(login_exitoso) + "\n+- Login fallidos: " + str(login_fallido) + "\n\n\n"


analyzeFtpLogs(filesLogPhp)
