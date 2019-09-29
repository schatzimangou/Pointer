import argparse
import logging

plugin_name= __name__.split(".")[-1]

#options MUST be one of GENERATOR, ANALYZER, PRESENTER
plugin_type = 'PRESENTER'

"""
This fuction must exist to define the arguments of its plugin.
Same argument name should not exist in two different plugins. 
It is recommended to append a keyword before each plugin argument for ease of usage.
If no arguments are needed for the plugin simply add the group and return parser
"""
def get_arguments(parser):
	"""
	group = parser.add_argument_group(plugin_name, 'Description of plugin here Type:%s',%PRESENTER)
	group.add_argument('--template_arg1')
	group.add_argument('--template_arg2')
	"""
	return parser

"""
Each plugin is responsible for checking its own arguments. If an error is identified not related to the type of arguments 
but to a logical issue with the provided values then return a striong error message to parser such as return 'provided value is not correct'.
If no error is identified then return None
"""
def arguments_check(plugin_args):
	"""
	if plugin_args['template_arg1'] is None:
		return "Argument template_arg1 must be provided"
	"""
	return None

def process(*args, **kwargs):
	"""
	logging.info("Name: %s" %plugin_name)
	logging.info("Type: %s" %plugin_type)
	logging.info("kwargs: %s"%kwargs)
	logging.info("kwargs: %s"%kwargs)
	logging.info(kwargs['args'])
	logging.info(kwargs['plugin_dir'])
	"""
	pass