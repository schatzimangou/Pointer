# coding: utf-8
import os
from lib.pluginmanager import PluginManager
import logging

logo =  '''
                                             
                                             
    ____          _         __               
   / __ \\ ____   (_)____   / /_ ___   _____  
  / /_/ // __ \\ / // __ \\ / __// _ \\ / ___/  
 / ____// /_/ // // / / // /_ /  __// /      
/_/     \\____//_//_/ /_/ \\__/ \\___//_/       
                                             
                                             
'''.decode('utf-8').split('\n')
dog = '''
                 _,)  
          _..._.-;-'  
       .-'     `(     
      /      ;   \\    
     ;.' ;`  ,;  ;    
    .'' ``. (  \\ ;    
   / f_ _L \\ ;  )\\    
   \\/|` '|\\/;; <;/    
  ((; \\_/  (()        
'''.split('\n')



for i, line in enumerate(logo):
  try:
    print dog[i]  + '' + line
  except:
    print line

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(module)s: %(message)s', datefmt='%d/%m/%Y %H:%M:%S', level=logging.INFO)

pm = PluginManager()
pm.run()