import argparse
import logging
import os
import shutil
from time import strftime, localtime, sleep

try:
    from jinja2 import Environment, FileSystemLoader
except:
    logging.error('Jinja2 module is missing. Please install it by running: pip install jinja2')


plugin_name= __name__.split(".")[-1]

#Set the plugin type
plugin_type = 'PRESENTER'

#Provide plugin arguments here and return them to plugin manager
def get_arguments(parser):
	group = parser.add_argument_group(plugin_name, 'Example plugin. Type %s' %plugin_type)
	group.add_argument('--example-argument1','-xa1', dest='example_argument1', type=str, help='A simple value')
	group.add_argument('--example-argument2','-xa2', dest='example_argument2', type=str, help='A simple value')
	group.add_argument('--example-argument3','-xa3', dest='example_argument3', type=str, help='A simple value')
	return parser

#Check user provided arguments. If no values were provided return errors
def arguments_check(plugin_args):
	if not plugin_args['example_argument1']:
		return "You must enter a value for --example-argument1/-xa1 argument."
	if not plugin_args['example_argument2']:
		return "You must enter a value for --example-argument2/-xa2 argument."
	if not plugin_args['example_argument3']:
		return "You must enter a value for --example-argument3/-xa3 argument."

#Process plugin arguments
def process(*args, **kwargs):
	logging.debug("Arguments: %s"%kwargs)

	# This is the way to retrieve user provided arguments
	plugin_args=kwargs['args']
	store_plugin=kwargs['plugin_dir']
	example_argument1 = plugin_args['example_argument1']
	example_argument2 = plugin_args['example_argument2']
	example_argument3 = plugin_args['example_argument3']

	logging.info("Starting plugin execution...")

	presentation_list = [{
	"argument1": example_argument1,
	"argument2": example_argument2,
	"argument3": example_argument3,
	}]

	create_report(store_plugin,presentation_list)
	logging.info("Plugin analysis completed!")

def create_report(store_plugin,presentation_list):
	logging.info("Starting report generation...")

	#Initialize report template and report destination dir
	templates_dir = os.path.abspath('lib/plugins/example_plugin/report_template')
	report_dir = os.path.abspath(os.path.join(store_plugin, 'report'))
	env = Environment( loader = FileSystemLoader(templates_dir))
	template_table = env.get_template('Example.html')
	filename_table = os.path.abspath(os.path.join(report_dir,'Example.html'))

	#remove previous report and prepare the dir structure
	if os.path.exists(report_dir):
		logging.info("Removing previous report...")
		shutil.rmtree(report_dir)
		sleep(5) # allow time to rm and create dir

	#if rm not completed allow some more time
	for retry in range(5):
		try:
			shutil.copytree(templates_dir, report_dir)
			sleep(2)
			break
		except:
			logging.error("Could not create report dir")

	logging.info("Generating report...")

	#generate report
	with open(filename_table, 'w') as fh:
		fh.write(template_table.render(data=presentation_list,time=strftime("%Y-%m-%d %H:%M:%S", localtime())))

	logging.info("Report generated sucessfully")