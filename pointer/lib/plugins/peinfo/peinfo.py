import argparse
import logging
import json
import os
import shutil
import hashlib
import binascii
from time import strftime, localtime

try:
    from jinja2 import Environment, FileSystemLoader
except:
    logging.error('Jinja2 module is missing. Please install it by running: pip install jinja2')

try:
    import pefile
except:
    logging.error('pefile module is missing. Please install it by running: pip install pefile')

try:
    import pype32
except:
    logging.error('pefile module is missing. Please install it by running: pip install pefile')


plugin_name= __name__.split(".")[-1]
plugin_type='ANALYZER'


def get_arguments(parser):
	group = parser.add_argument_group(plugin_name, 'Peinfo will calculate and display usefull information for a set of binaries')
	group.add_argument('--peinfo-directories','-pidirs', dest='peinfo_directories',  nargs='+', type=str,  help='A list of directories to display file information')
	group.add_argument('--peinfo-recursion','-pirec',action='store_true', dest='peinfo_recursion', help='Recursively search directory for files')
	group.add_argument('--peinfo-skip','-piskip',action='store_true', dest='peinfo_skip', help='Skip analysis and jump to report generation')	
	return parser

def arguments_check(plugin_args):
	if not plugin_args['peinfo_directories']:
		return "Please provide at least one directory with the argument -pidirs"

def process(*args, **kwargs):
	plugin_args = kwargs["args"]
	store_plugin = kwargs["plugin_dir"]

	pi_directories = [os.path.abspath(pidir) for pidir in plugin_args["peinfo_directories"]]
	pi_directory_recursive = plugin_args["peinfo_recursion"]
	pi_skip = plugin_args["peinfo_skip"]

	if not pi_skip:
		#assemble file list for analysis
		file_list = []
		for pidir in pi_directories:
			if pi_directory_recursive:
				logging.info("Looking recursively for files in directory %s" %pidir)
				for root, dirs, files in os.walk(pidir):
					if files is not None:
						for file in files:
							fabs = os.path.abspath(os.path.join(root,file))
							hnd = open(fabs,"rb")
							if hnd.read(2) == "MZ":
								file_list.append(os.path.abspath(os.path.join(root,file)))
			else:
				logging.info("Looking for files in directory %s" %pidir)
				for file in os.listdir(pidir):
					file = os.path.abspath(os.path.join(pidir,file))
					if os.path.isfile(file):
						hnd = open(file,"rb")
						if hnd.read(2) == "MZ":
							file_list.append(file)

	peinfo_list = []
	if not pi_skip:
		logging.info("Identified %d files. Starting analysis now."%len(file_list))
		#create peinfo_list
		
		for file in file_list:
			try:
				pe = pefile.PE(file)
				header_checksum = "0x%02x"%pe.OPTIONAL_HEADER.CheckSum
				calculated_checksum = "0x%02x"%pe.generate_checksum()
			except Exception as e:
				logging.error("Error analyzing checksum. Will set to -1: %s" %str(e))
				header_checksum = -1
				calculated_checksum = -1
			
			try:
				pe32 = pype32.PE(file,  fastLoad=True)
				overlay = "0x%x" % len(pe32.overlay)
				digital_signature_length = "0x%x" % len(pe32.signature)
			except Exception as e:
				logging.error("Error analyzing overlay and digital signature. Will set to -1: %s"%str(e))
				overlay = -1
				digital_signature_length = -1

			md5,sha1,sha256 =  calculate_hashes(file)
			details = [line.decode("ascii",'ignore')+'\n' for line in pecheck(file)]
			peinfo_list.append({
				'filepath':os.path.split(file)[0],
				'filename':os.path.split(file)[1],
				'filesize':os.path.getsize(file),
				'header_checksum': header_checksum,
				'calculated_checksum': calculated_checksum,
				'overlay_size': overlay,
				'signature_size': digital_signature_length,
				'md5': md5,
				'sha1': sha1,
				'sha256':sha256,
				'details': details
				})

	if not pi_skip:
		save_results(store_plugin,peinfo_list)

	create_report(store_plugin)
	logging.info("Plugin analysis completed!")


def calculate_hashes(filename, block_size=65536):
	md5 = hashlib.md5()
	sha1 = hashlib.sha1()
	sha256 = hashlib.sha256()
	with open(filename, 'rb') as f:
		for block in iter(lambda: f.read(block_size), b''):
			md5.update(block)
			sha1.update(block)
			sha256.update(block)
	return md5.hexdigest(),sha1.hexdigest(),sha256.hexdigest()

def save_results(store_plugin, peinfo_list):
	logging.info("Saving analysis results to disk...")
	results_dir = os.path.abspath(os.path.join(store_plugin, 'results'))

	if not os.path.exists(results_dir):
		logging.info("Creating results directory...")
		os.makedirs(results_dir)

	logging.info("%s pefile results will be saved to disk. Starting now..."%len(peinfo_list))
	for pefile in peinfo_list:
		fhash = pefile["sha256"]
		info_json = json.dumps(pefile)

		#logging.debug(json.dumps(json.loads(info_json), indent=4, sort_keys=True))

		fname = os.path.join(results_dir,fhash)
		with open(fname, 'w') as fh:
			fh.write(info_json)
	logging.info("Analysis results saved successfully disk under: %s" %os.path.join(store_plugin, 'results') )

def create_report(store_plugin):
	logging.info("Starting report generation...")
	templates_dir = os.path.abspath('lib/plugins/peinfo/report_template')
	report_dir = os.path.abspath(os.path.join(store_plugin, 'report'))
	env = Environment( loader = FileSystemLoader(templates_dir) )
	template_table = env.get_template('PEinfo.html')
	filename_table = os.path.abspath(os.path.join(report_dir,'PEinfo.html'))

	logging.info("Fetching previous analysis results...")
	#get state of ropinjector store
	results_dir = os.path.abspath(os.path.join(store_plugin, 'results'))
	peinfo_list = []
	for file in os.listdir(results_dir):
		with open(os.path.abspath(os.path.join(results_dir,file)), 'r') as fh:
			js = json.load(fh)
			peinfo_list.append(js)

	logging.info("A total of %d file analysis results were identified"%len(peinfo_list))

	#removing previous directory					
	if os.path.exists(report_dir):
		logging.info("Removing previous report...")
		shutil.rmtree(report_dir)

	for retry in range(5):
		try:
			shutil.copytree(templates_dir, report_dir)
			break
		except Exception as e:
			logging.error(str(e))
			return "Could not create report dir"

	#creating new report
	logging.info("Generating report...")
	with open(filename_table, 'w') as fh:
		fh.write(template_table.render(peinfo_list=peinfo_list,time=strftime("%Y-%m-%d %H:%M:%S", localtime())))

	logging.info("Report generated sucessfully")


#Code below is taken from this awesome tool: https://github.com/DidierStevens/DidierStevensSuite/blob/master/pecheck.py
#Cudos to that guy

def CIC(expression):
	if callable(expression):
		return expression()
	else:
		return expression

def IFF(expression, valueTrue, valueFalse):
	if expression:
		return CIC(valueTrue)
	else:
		return CIC(valueFalse)

def NumberOfBytesHumanRepresentation(value):
	if value <= 1024:
		return '%s bytes' % value
	elif value < 1024 * 1024:
		return '%.1f KB' % (float(value) / 1024.0)
	elif value < 1024 * 1024 * 1024:
		return '%.1f MB' % (float(value) / 1024.0 / 1024.0)
	else:
		return '%.1f GB' % (float(value) / 1024.0 / 1024.0 / 1024.0)

def pecheck(filename):
	output = []
	pe2 = pefile.PE(filename, fast_load=True)

	pe2.parse_data_directories( directories=[ 
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG'],
	#pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC'], # Do not parse relocations
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT'],
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT'] ] )

	output.append(pe2.dump_info())

	raw = pe2.write()
	output.append("PE check for :")
	output.append('Entropy: %f (Min=0.0, Max=8.0)' % pe2.sections[0].entropy_H(raw))
	output.append('MD5	 hash: %s' % hashlib.md5(raw).hexdigest())
	output.append('SHA-1   hash: %s' % hashlib.sha1(raw).hexdigest())
	output.append('SHA-256 hash: %s' % hashlib.sha256(raw).hexdigest())
	output.append('SHA-512 hash: %s' % hashlib.sha512(raw).hexdigest())
	for section in pe2.sections:
		output.append('%s entropy: %f (Min=0.0, Max=8.0)' % (''.join(filter(lambda c:c != '\0', str(section.Name))), section.get_entropy()))

	output.append('Dump Info:')
	output.append(pe2.dump_info())

	output.append('Entry point:')
	ep = pe2.OPTIONAL_HEADER.AddressOfEntryPoint
	ep_ava = ep + pe2.OPTIONAL_HEADER.ImageBase
	output.append('ep:		  0x%08x' % ep)
	output.append('ep address:  0x%08x' % ep_ava)
	for section in pe2.sections:
		if section.VirtualAddress <= ep and section.VirtualAddress + section.SizeOfRawData >= ep:
			output.append('Section:	 %s' % ''.join(filter(lambda c:c != '\0', str(section.Name))))
			output.append('ep offset:   0x%08x' % (section.PointerToRawData + ep - section.VirtualAddress))

	output.append('')
	output.append('Overlay:')
	overlayOffset = pe2.get_overlay_data_start_offset()
	if overlayOffset == None:
		output.append(' No overlay')
	else:
		output.append(' Start offset: 0x%08x' % overlayOffset)
		overlaySize = len(raw[overlayOffset:])
		output.append(' Size:		 0x%08x %s %.2f%%' %	 (overlaySize, NumberOfBytesHumanRepresentation(overlaySize), float(overlaySize) / float(len(raw)) * 100.0))
		output.append(' MD5:		  %s' % hashlib.md5(raw[overlayOffset:]).hexdigest())
		output.append(' SHA-256:	  %s' % hashlib.sha256(raw[overlayOffset:]).hexdigest())
		overlayMagic = raw[overlayOffset:][:4]
		if type(overlayMagic[0]) == int:
			overlayMagic = ''.join([chr(b) for b in overlayMagic])
		output.append(' MAGIC:		%s %s' % (binascii.b2a_hex(overlayMagic), ''.join([IFF(ord(b) >= 32, b, '.') for b in overlayMagic])))
		output.append(' PE file without overlay:')
		output.append('  MD5:		  %s' % hashlib.md5(raw[:overlayOffset]).hexdigest())
		output.append('  SHA-256:	  %s' % hashlib.sha256(raw[:overlayOffset]).hexdigest())
	
	return output

