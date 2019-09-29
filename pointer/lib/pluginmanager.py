import importlib
import argparse
import logging
import shutil
import sys
from time import strftime, localtime, sleep
from storemanager import StoreManager
import os

try:
    from jinja2 import Environment, FileSystemLoader
except:
    logging.error('Jinja2 module is missing. Please install it by running: pip install jinja2')

PLUGIN_DIR=os.path.dirname("lib/plugins/")

class PluginManager():

    def __init__(self):
        #get available plugins
        self.plugins_available = self._get_plugins_available()
        logging.debug('Available plugins %s'%str(", ".join(self.plugins_available)))

        #import plugins
        self.plugins_loaded = self._load_plugins()

        #generate argument parser according to loaded plugins
        self.args,self.arg_groups = self._generate_argument_parser()

        #setup logging
        level = {'debug':logging.DEBUG,'info':logging.INFO,'warning':logging.WARNING,'error':logging.ERROR,'critical':logging.CRITICAL}
        logging.info("Switching logging level to %s"%self.args.level)
        logging.getLogger().setLevel(level[self.args.level])

        #create store obj to manage plugin output
        self.store = StoreManager(self.args.store)

    def _load_plugins(self):
        plugins = {}
        for plugin in self.plugins_available:
            plugins[plugin] = importlib.import_module("lib.plugins.%s.%s"%(plugin,plugin), package="plugins")
        return plugins

    def call_plugin(self,plugin_name, *args, **kwargs):
        self.plugins_loaded[plugin_name].process(*args, **kwargs)

    def _get_plugins_available(self):
        return [p for p in os.listdir(PLUGIN_DIR) if os.path.isdir(os.path.join(PLUGIN_DIR,p))]

    def _generate_argument_parser(self):
        self.parser = argparse.ArgumentParser(description='Pointer is a tool to speedup malware samples analysis ')
        self.parser.add_argument('-l','--level', type=str, dest='level', choices=['debug','info','warning','error','critical'], default='info', help='Set the logging level')
        self.parser.add_argument('-s','--store', dest='store', type=str, default='Pointer Store', help='Set the directory of the outpout files and analysis results')
        self.parser.add_argument('-o','-open-browser', action='store_true', dest='open', help='Open generated report in browser')
	
        command_group = self.parser.add_mutually_exclusive_group()
        command_group.add_argument('-p','--plugins', nargs='+', dest='plugins', choices=self.plugins_loaded.keys(), help='select the plugins to run')
        command_group.add_argument('-e','--export',  action='store_true', dest='export', help='export the report')

        # go through each plugin and collect arguments
        for plugin in self.plugins_loaded:
            self.plugins_loaded[plugin].get_arguments(self.parser)
        args = self.parser.parse_args()

        arg_groups={}
        for group in self.parser._action_groups:
            arg_groups[group.title] = {a.dest:getattr(args,a.dest,None) for a in group._group_actions}

        return args, arg_groups

    def run(self):
        if self.args.plugins:
            # checking which arguments belong to which group because argparse is stupid
            for plugin in self.args.plugins:
                try:
                    message = self.plugins_loaded[plugin].arguments_check(self.arg_groups[plugin])
                    if message:
                        self.parser.error(message)
                except KeyError, e:# if no arguments are specified then the above will through na Exception
                    pass
            self.exec_plugins()
        elif self.args.export:
            self.store.export()

    def exec_plugins(self):
        # initialize plugins
        plugins_chosen = self.args.plugins
        if 'all' in self.args.plugins:
            plugins_chosen = self.plugins_loaded.keys()

        self.store.prepare_store(plugins_chosen)

        logging.info("Executing plugins: %s"%", ".join(plugins_chosen))
        sort_order = {"GENERATOR": 0, "ANALYZER": 1, "PRESENTER": 2}
        plugins_chosen.sort(key=lambda val: sort_order[self.plugins_loaded[val].plugin_type])
        logging.info("Plugins will be executed with the following order: %s"%", ".join(plugins_chosen))

        # run plugins
        for plugin in plugins_chosen:
            args = []
            if plugin in self.arg_groups:
                args = self.arg_groups[plugin] # if arguments where provided by the user
            message =  self.plugins_loaded[plugin].process(args=args,plugin_dir=self.store.plugin_dirs[plugin])
            if message:
                logging.error("%s: %s"%(plugin,message))
        self.assemble_report()

    def assemble_report(self):
        report_list = []
        for plugin in self.plugins_available:
            try:
                plugin_report_dir = os.path.join(self.store.root,plugin,"report")
                for f in os.listdir(plugin_report_dir):
                    if f.endswith(".html"):
                        report_list.append({'name': f.split(".html")[0], 'path': os.path.relpath(os.path.abspath(os.path.join(plugin_report_dir,f)),self.store.report)})
            except:
                pass

        templates_dir = os.path.abspath('templates/report')
        report_dir = self.store.report
        env = Environment( loader = FileSystemLoader(templates_dir) )
        template = env.get_template('pointer.html')
        filename = os.path.join(self.store.report,'pointer.html')

        if os.path.exists(report_dir):
            shutil.rmtree(report_dir)
        for retry in range(5):
            try:
                shutil.copytree(templates_dir, report_dir)
                sleep(5)
                break
            except:
                logging.error("Could not create report dir")
                sys.exit(1)

        with open(filename, 'w') as fh:
            fh.write(template.render(store=self.args.store,time=strftime("%Y-%m-%d %H:%M:%S", localtime()),reports=report_list))
        logging.info("Report at %s"%filename)
        if self.args.open:
            import webbrowser
            webbrowser.open(filename)