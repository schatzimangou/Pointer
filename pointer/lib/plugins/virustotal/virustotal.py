import argparse
import logging
from virustotalapi import vt
import json
import os
from time import strftime, localtime, sleep, time
import shutil
import hashlib
import re

try:
    from jinja2 import Environment, FileSystemLoader
except:
    logging.error('Jinja2 module is missing. Please install it by running: pip install jinja2')

plugin_name= __name__.split(".")[-1]
plugin_type='ANALYZER'

def get_arguments(parser):
	group = parser.add_argument_group(plugin_name, 'The VirusTotal plugin provides all the required functionality to automate the analysis of files using the VirusTotal online service.  Type %s' %plugin_type)
	group.add_argument('--virustotal-key','-vtkey', dest='virustotal_key', type=str,  help='The VirusTotal API Key.')
	group.add_argument('--virustotal-limit','-vtlim', dest='virustotal_limit', type=int, default=4,  help='The limit of requests per minute.')
	group.add_argument('--virustotal-dir','-vtdir', dest='virustotal_dir', type=str,  help='A directory of files to analyze.')
	group.add_argument('--virustotal-recursion','-vtrec',action='store_true', dest='virustotal_recursion', help='Recursively search the directory for files')
	group.add_argument('--virustotal-file-types','-vtfmt', nargs='+', dest='virustotal_file_types', type=str, default=['exe'],  help='The extension of the files that will be uploaded')
	group.add_argument('--virustotal-noscan','-vtno', action='store_true', dest='virustotal_noscan', help='Fetch the VirusTotal reports for files already submitted. For the rest of the files skip analysis')
	group.add_argument('--virustotal-mixscan','-vtmix', action='store_true', dest='virustotal_mixscan', help='Fetch the VirusTotal reports for files already submitted. For the rest of the files upload and fetch the report.')
	group.add_argument('--virustotal-new','-vtnew', action='store_true', dest='virustotal_new', help='Scan only files for which reports do not exist in the store.')
	group.add_argument('--virustotal-immediate','-vtimm', type=int, dest='virustotal_immediate', help='Send x requests for and then query for reports. This mode is useful when scanning a large dataset and ensures that you will retrieve results as fast as possible. This value should never be greater than vtlim.')
	group.add_argument('--virustotal-skip','-vtskip', action='store_true', dest='virustotal_skip', help='Skip plugin analysis and jump to report generation. Useful for debugging reasons.1')
	return parser


def arguments_check(plugin_args):
	if not plugin_args["virustotal_skip"]:
		if not plugin_args['virustotal_key']:
			return "You need an api key to run this plugin"
		if not plugin_args['virustotal_dir']:
			return "You must specify a directory of files to run against virustotal"
		if ((plugin_args['virsutotal_mixscan'] and plugin_args['virustotal_noscan'])	or 
		(plugin_args['virsutotal_mixscan'] and plugin_args['virustotal_immediate'])	or
		(plugin_args['virustotal_noscan'] and plugin_args['virustotal_immediate'])):
			return "Contradicting modes chosen. Please choose one mode"	

def process(*args, **kwargs):
	plugin_args = kwargs["args"]
	store_plugin = kwargs["plugin_dir"]
	vt_skip = plugin_args["virustotal_skip"]

	if not vt_skip:
		virustotal = vt()
		virustotal.setkey(plugin_args["virustotal_key"])

		#search and retrive file paths of files specified by the user arguments
		scan_directory = os.path.abspath(plugin_args["virustotal_dir"])

		scan_file_extensions = plugin_args["virustotal_file_types"]
		scan_directory_recursive = plugin_args["virustotal_recursion"]
		scan_new = plugin_args["virustotal_new"]

		#mode selection
		mode = 'scan'
		if plugin_args["virustotal_mixscan"]:
			mode = 'mixscan'
		elif plugin_args["virustotal_noscan"]:
			mode = 'noscan'
		elif plugin_args["virustotal_immediate"]:
			mode = 'immediate'

		hash_list = []
		if scan_new:
			results_dir = os.path.join(store_plugin,'results')
			if os.path.exists(results_dir):
				hash_list = os.listdir(results_dir)

		# retrieve files for scan according to arguments
		file_list = []
		if scan_directory_recursive:
			logging.info("Looking recursively for files in directory %s..." %scan_directory)
			for root, dirs, files in os.walk(scan_directory):
				if files is not None:
					for file in files:
						fpath = os.path.abspath(os.path.join(root,file))
						extension = os.path.splitext(fpath)[1].lstrip('.')
						if extension in scan_file_extensions:
							if scan_new:
								if sha256_checksum(fpath) not in hash_list:
									file_list.append(fpath)
							else:
								file_list.append(fpath)
		else:
			logging.info("Looking for files in directory %s..." %scan_directory)
			for file in os.listdir(scan_directory):
				file = os.path.abspath(os.path.join(scan_directory,file))
				if os.path.isfile(file):
					fpath = file
					extension = os.path.splitext(fpath)[1].lstrip('.')
					if extension in scan_file_extensions:
						if scan_new:
							if sha256_checksum(fpath) not in hash_list:
								file_list.append(fpath)
						else:
							file_list.append(fpath)

		#file_list should have the correct files by now.
		logging.info("Found %d files for scanning..." %len(file_list))

		scan_limit = plugin_args["virustotal_limit"]

		logging.info("Starting scanning at a rate of %d requests per minute..." %scan_limit)
		
		start_time = time()
		req_counter = 0
		#start scan
		scan_results = []
		scan_ids = [] #scan_ids from files submitted in virus total and pending scan.

		resuts_saved = 0
		files_uploaded = 0

		for file_counter,file in enumerate(file_list):

			#if file_counter+1 ==3: #speed things up
			#	break

			logging.debug("Starting scan for file %s" %file)
		
			if mode == 'noscan' or mode =="mixscan":
				start_time = vtsleep(req_counter,scan_limit,start_time) #check if we need to sleep
				res = virustotal.getfilereport(file)
				req_counter +=1
				#try loading the response
				try:
					res = json.loads(res)
				except Exception as e: #usually occurs when we have exceeded the virustotal api call limit
					logging.error("Could not load response: %s."%str(e))
					logging.error("File will be skipped!")
					continue

				#logging.debug("response code is %d mode %s" %(res["response_code"],mode))
				# case response code 1 - report was found for noscan and mixscan: get report
				if res["response_code"] == 1:
					scan_result = {'name':file,	'results':res}
					save_result(store_plugin,scan_result,scan_directory)
					resuts_saved+=1
					logging.info("Progress: %s/%s file results retrieved"%(resuts_saved,len(file_list)))

				#case response code 0 - report not found or response code -2  and noscan: skip 
				elif (res["response_code"] == 0 or res["response_code"] == -2) and mode == 'noscan':
					scan_result = {'name':file,	'results':res}
					save_result(store_plugin,scan_result,scan_directory)
					resuts_saved+=1
					logging.info("Progress: %s/%s file results retrieved"%(resuts_saved,len(file_list)))

				#case response code 0 - report was not found for mixscan: upload file for scan.
				elif mode == 'mixscan':
					if (res["response_code"] == 0): #file does not exist in vt db
						#submit file to queue and add id to scan_ids
						start_time = vtsleep(req_counter,scan_limit,start_time)
						res = virustotal.scanfile(file)
						req_counter +=1
						# add scan_id to queue. Implied case here is response code -2 - file pending analysis.
						scan_ids.append({"file":file,"scan_id":res['scan_id']})
						files_uploaded+=1
						logging.info("Progress: %s/%s files uploaded"%(files_uploaded,len(file_list)))
			elif mode == 'immediate':
				start_time = vtsleep(req_counter,scan_limit,start_time)
				res = virustotal.scanfile(file)
				req_counter +=1
				scan_ids.append({"file":file,"scan_id":res['scan_id']})
				files_uploaded+=1
				logging.info("Progress: %s/%s files uploaded"%(files_uploaded,len(file_list)))
				
				if req_counter % (scan_limit * 2)  == 0:
					if len(scan_ids)!=0:
						start_time = time()
						vtsleep(req_counter,scan_limit,start_time)

						while len(scan_ids) !=0: # so long as we have scan ids in list loop through every item to find results
							logging.info("Pending %d file reports. Starting queries for results" %(len(scan_ids)))
							for scan in scan_ids:
								#again sleep time between requests. Must do that due to virustotal free api restrictions
						
								start_time = vtsleep(req_counter,scan_limit,start_time)
								res = virustotal.getfilereport(scan['scan_id'])
								req_counter+=1
								try:
									res = json.loads(res)
								except Exception as e: #usually occurs when we have exceeded the virustotal api call limit
									logging.error("Could not load response: %s."%str(e))
									logging.error("File will be skipped!")
									continue

								if res["response_code"] == 1:
									scan_result = {'name':scan['file'],	'results':res}
									save_result(store_plugin,scan_result,scan_directory)
									scan_ids.remove(scan)
									resuts_saved+=1
									logging.info("Progress: %s/%s file results retrieved"%(resuts_saved,len(file_list)))
								elif res["response_code"] == -2:
									logging.info("Progress: Pending %s results"%len(scan_ids))
								elif res["response"] == 0:
									logging.error("All files should be submitted by now. This should never happen. logical error....hmmm...")
			else: #no mode given by user so scan everything
				start_time = vtsleep(req_counter,scan_limit,start_time)
				res = virustotal.scanfile(file)
				req_counter +=1
				scan_ids.append({"file":file,"scan_id":res['scan_id']})
				files_uploaded+=1
				logging.info("Progress: %s/%s files uploaded"%(files_uploaded,len(file_list)))

		#if mode is mixscan or scan start querying results
		# start looping  for queued files scan results

		if len(scan_ids)!=0:

			start_time = time()
			vtsleep(req_counter,scan_limit,start_time)
			logging.info("Pending %d file reports. Starting queries for results" %(len(scan_ids)))
			while len(scan_ids) !=0: # so long as we have scan ids in list loop through every item to find results
				
				for scan in scan_ids:
					#again sleep time between requests. Must do that due to virustotal free api restrictions
					
					start_time = vtsleep(req_counter,scan_limit,start_time)
					res = virustotal.getfilereport(scan['scan_id'])
					req_counter+=1
					try:
						res = json.loads(res)
					except Exception as e: #usually occurs when we have exceeded the virustotal api call limit
						logging.error("Could not load response: %s."%str(e))
						logging.error("File will be skipped!")
						continue

					if res["response_code"] == 1:
						scan_result = {'name':scan['file'],	'results':res}
						save_result(store_plugin,scan_result,scan_directory)
						scan_ids.remove(scan)
						resuts_saved+=1
						logging.info("Progress: %s/%s file results retrieved"%(resuts_saved,len(file_list)))
					elif res["response_code"] == -2:
						logging.info("Progress: Pending %s results"%len(scan_ids))

					elif res["response"] == 0:
						logging.error("All files should be submitted by now. This should never happen. logical error....hmmm...")


	create_report(store_plugin)
	logging.info("Plugin analysis completed!")

def vtsleep(counter,limit,stime):
	#logging.debug("counter %d limit %d stime %d" %(counter,limit,stime))
	if ((counter != 0) and (counter % limit == 0)):
		sleeptime =stime + 65 - time() #65 to be safe
		if sleeptime > 0:
			logging.info("Requests performed: %d. Sleeping for %d seconds..." %(counter,sleeptime))
			sleep(sleeptime)
		return time() #return new start time
	return stime

def save_result(store_plugin,scan_result,scan_directory):
	results_dir = os.path.abspath(os.path.join(store_plugin, 'results'))
	#create results directory if it does not exist
	if not os.path.exists(results_dir):
		logging.info("Creating directory %s"%results_dir)
		os.makedirs(results_dir)

	logging.debug("Saving results for %s" %scan_result['name'])

	#files will be saved with their sha256 hash.If we are lucky and have a report then we use the hash from the report. Otherwise we calculate it.
	if (scan_result["results"] is not None) and (scan_result["results"]["response_code"]!=0):
		fsha256 = scan_result["results"]["sha256"]
	else:
		#get absolute file path
		fpath = os.path.join(os.path.normpath(os.path.join(scan_directory, os.pardir)),scan_result["name"])
		#calculate hash
		fsha256 = sha256_checksum(fpath)
		fsha1 = sha1_checksum(fpath)
		fmd5 = md5_checksum(fpath)
		#add empty scans results for correct report generation
		scan_result["results"]["scans"] = {}
		scan_result["results"]["positives"] = 0
		scan_result["results"]["total"] = 0
		scan_result["results"]["unique"] = 0
		scan_result["results"]["scan_date"] = "N/A"
		scan_result["results"]["sha256"] = fsha256
		scan_result["results"]["sha1"] = fsha1
		scan_result["results"]["md5"] = fmd5
	
	fname = os.path.join(results_dir,fsha256)
	with open(fname, 'w') as fh:
		fh.write(json.dumps(scan_result))

def sha256_checksum(filename, block_size=65536):
	sha256 = hashlib.sha256()
	with open(filename, 'rb') as f:
		for block in iter(lambda: f.read(block_size), b''):
			sha256.update(block)
	return sha256.hexdigest()

def sha1_checksum(filename, block_size=65536):
	sha1 = hashlib.sha1()
	with open(filename, 'rb') as f:
		for block in iter(lambda: f.read(block_size), b''):
			sha1.update(block)
	return sha1.hexdigest()

def md5_checksum(filename, block_size=65536):
	md5 = hashlib.md5()
	with open(filename, 'rb') as f:
		for block in iter(lambda: f.read(block_size), b''):
			md5.update(block)
	return md5.hexdigest()

def create_report(store_plugin):
	logging.info("Starting report generation...")
	templates_dir = os.path.abspath('lib/plugins/virustotal/report_template')
	report_dir = os.path.abspath(os.path.join(store_plugin, 'report'))
	env = Environment( loader = FileSystemLoader(templates_dir) )
	template_vt = env.get_template('VirusTotal.html')
	filename_vt = os.path.abspath(os.path.join(report_dir,'VirusTotal.html'))

	template_vteng = env.get_template('VirusTotal Engines.html')
	filename_vteng = os.path.abspath(os.path.join(report_dir,'VirusTotal Engines.html'))

	template_vtsig = env.get_template('VirusTotal Signatures.html')
	filename_vtsig = os.path.abspath(os.path.join(report_dir,'VirusTotal Signatures.html'))

	template_vtdash = env.get_template('VirusTotal Dashboard.html')
	filename_vtdash = os.path.abspath(os.path.join(report_dir,'VirusTotal Dashboard.html'))

	#fetch previous scans from store
	logging.info("Fetching previous scan results...")
	results_dir = os.path.abspath(os.path.join(store_plugin, 'results'))
	file_results = []

	if not os.path.exists(results_dir):
		logging.error("Error path %s does not exist."%results_dir)
		logging.error("Aborting plugin execution!")
		return 

	for file in os.listdir(results_dir):
		with open(os.path.abspath(os.path.join(results_dir,file)), 'r') as fh:
			js = json.load(fh)
			file_results.append(js)

	logging.info("A total of %d scan results were identified"%len(file_results))

	if os.path.exists(report_dir):
		logging.info("Removing previous report...")
		shutil.rmtree(report_dir)

	for retry in range(5):
		try:
			shutil.copytree(templates_dir, report_dir)
			sleep(5)
			break
		except Exception as e:
			logging.error(str(e))
			return "Could not create report dir"

	total_positives = 0 #to calculate overall evasion
	total_total = 0 #to calculate overall evasion
	total_positive_files = 0
	logging.info("Calculating engine and signature results...")

	#ugly way to retrieve unique count of detections and create the engine report dataset.
	#Also generate the engine and signature result dics for the presentation. Better here than with jinja.
	engine_results = {}
	signature_results = {}
	keyword_list = []
	antivirus_keywords = {}
	for file in file_results:
		file["fullname"] = file["name"]
		file["filepath"] = os.path.split(file["name"])[0]
		file["filename"] = os.path.split(file["name"])[1]
		sigs = []
		file["keywords"] = []
		if file["results"] is not None and file["results"]["response_code"]!=0:
			total_positives+= file["results"]["positives"]
			total_total += file["results"]["total"]
			if file["results"]["positives"] >0:
				total_positive_files += 1
	 		for antivirus in file["results"]["scans"]:
	 			if antivirus not in engine_results.keys():
					engine_results[antivirus] = {'results':[],'unique':0}
				if antivirus not in antivirus_keywords.keys():
					antivirus_keywords[antivirus] = []
				file_antivirus_signature = file["results"]["scans"][antivirus]['result']
				if file_antivirus_signature is not None:
					# engine results part.
					engine_results[antivirus]['results'].append(
					{
					"fullname": file["fullname"],
					"filepath": file["filepath"],
					"filename": file["filename"],
					"sha1": file["results"]["sha1"],
					"md5": file["results"]["md5"],
					"sha256": file["results"]["sha256"],
					"scan_date": file["results"]["scan_date"],
					"permalink": file["results"]["permalink"],
					"signature": file_antivirus_signature
					}
					)

					#signature results part
					# check if signature exists in dic
					if file_antivirus_signature not in signature_results.keys():
						signature_results[file_antivirus_signature] = {'results':[],'unique_files':0,'unique_engines':0}
					
					# add signature data
					signature_results[file_antivirus_signature]['results'].append(
					{
					"fullname": file["fullname"],
					"filepath": file["filepath"],
					"filename": file["filename"],
					"sha1": file["results"]["sha1"],
					"md5": file["results"]["md5"],
					"sha256": file["results"]["sha256"],
					"scan_date": file["results"]["scan_date"],
					"permalink": file["results"]["permalink"],
					"engine": antivirus
					}
					)

					#append all keywords from detection
					signature_keywords = re.findall('[A-Za-z]{3,}',file_antivirus_signature.lower())
					file["keywords"] += signature_keywords
					keyword_list += signature_keywords
					antivirus_keywords[antivirus] += signature_keywords

					# unique signature part for virustotal.html
					if file["results"]["scans"][antivirus]['result'] not in sigs:
						sigs.append(file["results"]["scans"][antivirus]['result'])

			file["results"]["unique"] = (len(sigs))
			file["keywords"] = [(word,file["keywords"].count(word)) for word in set(file["keywords"])]
			file["keywords"] = sorted(file["keywords"], key=lambda tup: tup[1], reverse=True)
	
	# needed for virustotal signatures.html
	keyword_list = [(word,keyword_list.count(word)) for word in set(keyword_list)]
	keyword_list = sorted(keyword_list, key=lambda tup: tup[1], reverse=True)
	num_keywords_appearances = sum([keyword[1] for keyword in keyword_list])
	num_of_signatures = len(signature_results)
	num_of_scanned_files = len(file_results) # for signature evasion report


	#unique files and unique engines part for virustotal signatures.html
	for signature in signature_results.keys():
		signature_files = []
		signature_engines = []
		for result in signature_results[signature]['results']:
			if result["filename"] not in signature_files:
				signature_files.append(result["filename"])

			if result["engine"] not in signature_engines:
				signature_engines.append(result["engine"])
			
		signature_results[signature]["unique_files"] = signature_files
		signature_results[signature]["unique_engines"] = signature_engines

	# needed for virustotal signatures.html
	signature_list = []
	for signature in signature_results.keys():
		signature_list.append((signature,len(signature_results[signature]['results'])))
	signature_list = sorted(signature_list, key=lambda tup: tup[1], reverse=True)
	

	#unique signature part for virustotal engines.html
	engine_signature_dict = {} #dictionary with all engines and signatures triggered
	for engine in engine_results.keys():
		engusigs = []
		for result in engine_results[engine]['results']:
			if engine not in engine_signature_dict:
				engine_signature_dict[engine] = []
			engine_signature_dict[engine].append(result["signature"])

			if result["signature"] not in engusigs:
				engusigs.append(result["signature"])
		engine_results[engine]["unique"] = engusigs

	for engine,signatures in engine_signature_dict.items():
		engine_signature_dict[engine] = [(sig,signatures.count(sig)) for sig in set(signatures)]

	# needed for virustotal engines.html
	engine_list = []
	for engine in engine_results.keys():
		engine_list.append((engine,len(engine_results[engine]['results'])))
	engine_list = sorted(engine_list, key=lambda tup: tup[1], reverse=True)


	#calculate keywords in antivirus signatures among the sample
	for antivirus,keywords in antivirus_keywords.items():
		antivirus_keywords[antivirus] = [(word,antivirus_keywords[antivirus].count(word)) for word in set(antivirus_keywords[antivirus])]
		antivirus_keywords[antivirus] = sorted(antivirus_keywords[antivirus], key=lambda tup: tup[1], reverse=True)


	vt_stats={
		'num_keywords_appearances':num_keywords_appearances,
		'num_of_signatures':num_of_signatures,
		'num_of_scanned_files':num_of_scanned_files,
		'total_positives':total_positives,
		'total_total':total_total,
		'total_positive_files':total_positive_files,
		'total_positive_engines': len([engine[0] for engine in engine_list if engine[1] > 0]),
		'total_engines': len(engine_list),
		'signature_cloud': ','.join((signature[0]+',') * signature[1] for signature in signature_list if signature[1] > 2),
		'engine_cloud': ','.join((engine[0]+',') *engine[1] for engine in engine_list),
		'keyword_cloud': ' '.join((keyword[0]+' ') * keyword[1] for keyword in keyword_list if keyword[1] > 1)
	}


	logging.info("Generating reports...")
	with open(filename_vtsig, 'w') as fh:
		fh.write(template_vtsig.render(keyword_list=keyword_list,vt_stats=vt_stats,signature_list=signature_list,results=signature_results,time=strftime("%Y-%m-%d %H:%M:%S", localtime())))

	with open(filename_vteng, 'w') as fh:
		fh.write(template_vteng.render(keyword_list=keyword_list,antivirus_keywords=antivirus_keywords,vt_stats=vt_stats,signature_results=signature_results,engine_signature_dict=engine_signature_dict,results=engine_results,time=strftime("%Y-%m-%d %H:%M:%S", localtime())))

	with open(filename_vt, 'w') as fh:
		fh.write(template_vt.render(keyword_list=keyword_list,signature_list=signature_list,engine_list=engine_list,vt_stats=vt_stats,file_results=file_results,time=strftime("%Y-%m-%d %H:%M:%S", localtime())))

	with open(filename_vtdash, 'w') as fh:
		fh.write(template_vtdash.render(engine_signature_dict=engine_signature_dict,signature_results=signature_results,vt_stats=vt_stats,engine_list=engine_list,signature_list=signature_list,keyword_list=keyword_list,time=strftime("%Y-%m-%d %H:%M:%S", localtime())))

	logging.info("Reports generated successfully")
