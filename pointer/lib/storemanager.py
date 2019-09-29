import os
import logging
import time
import shutil

PLUGIN_DIR=os.path.dirname("lib/plugins/")

class StoreManager():
	def __init__(self,store):
		self.store = store
		self.root=os.path.abspath(store)
		self.report=os.path.abspath(os.path.join(self.root, "report"))
		self.plugin_dirs = {}

	def prepare_store(self,plugins_chosen):
		#create store
		logging.info("Preparing store %s" %self.root)
		if not os.path.exists(self.root):
			os.makedirs(self.root)
		else:
			logging.info("Directory exists. Skipping...")

		if not os.path.exists(self.report):
			os.makedirs(self.report)
		
		"""
		logging.info("Copying original files...")
		if len(os.listdir(self.dir)) == 0:
			logging.error("Directory has no files! Nothing to do!")
			sys.exit(1)
			
		for f in os.listdir(self.dir):
			logging.debug("Copying file %s"%f)
			shutil.copy2(os.path.join(self.dir, f),self.original)
		self.original_contents=[os.path.abspath(os.path.join(self.original,f)) for f in os.listdir(self.original)]
		"""
		
		for plugin in plugins_chosen:
			self.plugin_dirs[plugin] = os.path.join(self.root, plugin)
			if not os.path.exists(self.plugin_dirs[plugin]):
				os.makedirs(self.plugin_dirs[plugin])

	def export(self):
		if not os.path.exists(self.root):
			logging.error("Store %s does not exist. Nothing to do." %self.root)
			return

		if not os.path.exists(self.report):
			logging.error("Report directory %s does not exist. Maybe no plugins have run yet.." %self.report)
			return

		try:
			export_dir = os.path.abspath("Pointer Report %s %s"%(self.store,time.strftime("%Y-%m-%d %H.%M.%S", time.localtime())))
			os.makedirs(export_dir)
		except Exception as e:
			logging.error(str(e))
			logging.error("Cannot create export directory.Aborting...")
			return

		logging.info("Starting export of reports in directory %s. This might take some time..." %self.report)
		for directory in os.listdir(self.root):
			is_report =''
			if directory != 'report':
				is_report = 'report'

			for retry in range(5):
				logging.debug("Copying %s to %s"%(os.path.join(self.root,directory,is_report), os.path.join(self.root,export_dir,is_report)))
				try:
					shutil.copytree(os.path.join(self.root,directory,is_report), os.path.join(self.root,export_dir,directory,is_report))
					time.sleep(5)
					break
				except Exception as e:
					logging.error(str(e))
					return 

		logging.info("Export complete! Report directory is %s"%export_dir)
