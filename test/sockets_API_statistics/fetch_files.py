#This file_fetch python file is used to download all network applications 
#source code packages which are defined under the section called "applications"
#in the sockets_analysis.conf configuration file and decompress them.

#Licence: GUN/GPL
#Authors: Tao Wan <twan@cc.hut.fi>

from conf_reader import ConfReader
import os, sys
import shutil

#!/usr/bin/python

class fetchNetApps:
	def __init__(self, apps_list):
		self.net_apps_list = apps_list
		self.apps_path = os.path.join(os.environ['PWD'],'applications')
		
		#Check whether it already exists network applications directory,
		#delete if existed, if not it will create new one
		if os.path.exists(self.apps_path):
			print "delete the existing apps directory", self.apps_path
			#delete dirs recursively
			shutil.rmtree(self.apps_path)
		print "create the applications directory"
		os.mkdir('applications')


	def download_apps(self):
		#check what OS is, linux , unix, windows or Mac
		uname = os.uname()
		#if it is Linux system, wget shell command is needed 
		if "Linux" in uname:
			download_command = "wget --directory-prefix=applications -c "
			for down_link in self.net_apps_list:
				print "Downloading", down_link[0], "from ", down_link[1]
				os.system(download_command + down_link[1])
	
	
	def decompress_apps(self):
		dirs = " --directory ./applications " #define where to decompress
		tar_command_1 = "tar jxf " 
		tar_command_2 = "tar xfz "
		if os.path.exists(self.apps_path):
			for name in os.listdir(self.apps_path):
				#print name.endswith('bz2')
				#print name.endswith('gz')
				
				if name.endswith('bz2'):
					full_name = os.path.join(self.apps_path, name)
					print tar_command_1 + full_name + dirs
					os.system(tar_command_1 + full_name + dirs)
					os.remove(full_name)
				if name.endswith('gz') or name.endswith('tgz'):
					full_name = os.path.join(self.apps_path, name)
					print tar_command_2 + full_name + dirs
					os.system(tar_command_2 + full_name + dirs)
					os.remove(full_name)


		
