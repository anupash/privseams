#!/usr/bin/python
import glob, os, sys, xml.dom.minidom

 
### Constants ###
INFO_FILE_PATH = 'project_info.xml'

APPLICATION_TAG_NAME  = 'application'
APPLICATION_ATTR_NAME = 'name'
APPLICATION_PATH_NAME = 'path'

MODULES_DIR      = 'modules'
MODULE_INFO_FILE = 'module_info.xml'

HEADER_FILE_DIR    = MODULES_DIR
HEADER_FILE_SUFFIX = '_modules.h'


### Functions ###

# Parses the XML document at 'path' and returns a list of application names
def parse_info_file(path):

    file = open(path, "r")
    dom = xml.dom.minidom.parse(file)
    file.close()
    
    apps = {}
    
    for current_app in dom.getElementsByTagName(APPLICATION_TAG_NAME):
        name = str(current_app.attributes[APPLICATION_ATTR_NAME].value)
        path = str(current_app.attributes[APPLICATION_PATH_NAME].value)
        apps[name] = path
        
    compile_type = 'all'
    if 0 < len(dom.getElementsByTagName('compile_type')):
        node = dom.getElementsByTagName('compile_type')[0];
        compile_type = node.childNodes[0].nodeValue
        
    # Read list of disabled modules from command line and convert to set
    disabled_modules = sys.argv
    disabled_modules.pop(0)
    disabled_modules = set(disabled_modules)
    
    # Read list of disabled modules from configuration file and add to set (unique)
    if 0 < len(dom.getElementsByTagName('disabled_modules')):
        for node in dom.getElementsByTagName('disabled_modules')[0].getElementsByTagName('module'):
            disabled_modules.add(str(node.attributes['name'].value))
    
    return (apps, compile_type, disabled_modules)

# Parses the XML document at 'path' and returns a dictionary with module info
def parse_module_info(path, applications):
    
    file = open(path, "r")
    dom = xml.dom.minidom.parse(file)
    file.close()
    
    module_info = {}
    
    module_name = str(dom.getElementsByTagName('module')[0].attributes['name'].value)
    module_info['version'] = str(dom.getElementsByTagName('module')[0].attributes['version'].value)
    
    module_info['requires'] = []
    if 0 < len(dom.getElementsByTagName('requires')):
        for node in dom.getElementsByTagName('requires')[0].getElementsByTagName('module'):
            current_req = {}
            current_req['name'] = str(node.attributes['name'].value)
            if 'minversion' in node.attributes.keys():
                current_req['minversion'] = str(node.attributes['minversion'].value)
            if 'maxversion' in node.attributes.keys():
                current_req['maxversion'] = str(node.attributes['maxversion'].value)
    
            module_info['requires'].append(current_req)
        
    module_info['conflicts'] = []
    if 0 < len(dom.getElementsByTagName('conflicts')):
        for node in dom.getElementsByTagName('conflicts')[0].getElementsByTagName('module'):
            current_con = {}
            current_con['name'] = str(node.attributes['name'].value)
            if 'minversion' in node.attributes.keys():
                current_con['minversion'] = str(node.attributes['minversion'].value)
            if 'maxversion' in node.attributes.keys():
                current_con['maxversion'] = str(node.attributes['maxversion'].value)
    
            module_info['conflicts'].append(current_con)
    
    module_info['application'] = {}
    if 0 == len(dom.getElementsByTagName('application')):
        print '|\n|    WARNING in configuration of ' + module_name + ':',
        print 'no application tag found'
        print '|    Please check configuration file'
        raise Error()
        
    for current_app in dom.getElementsByTagName('application'):
        app_info = {}
        name = str(current_app.attributes['name'].value)
        if False == (name in applications.keys()):
            print '|\n|    WARNING in configuration of ' + module_name + ':',
            print 'unknown application ' + name
            print '|    Please check configuration file'
            raise Error()
            
        app_info['header_file'] = str(current_app.attributes['header_file'].value)
        app_info['init_function'] = str(current_app.attributes['init_function'].value)
        app_info['linkcommand'] = str(current_app.attributes['linkcommand'].value)
        module_info['application'][name] = app_info
    
    return (module_name, module_info)
    
# Tries to read the XML configuration files for all sub-folders in the given 
# directory and returns a dictionary containing the module information
def read_module_info(MODULES_DIR, disabled_modules, applications, compile_type):
    
    # Initialize output variable
    module_info = {}
    
    # Iterate through all sub directories in MODULES_DIR
    for current_module in glob.glob(MODULES_DIR + '/*/'):
        cont = False
        # Check if current_module is disabled
        for disabled in disabled_modules:
            if current_module == os.path.join(MODULES_DIR, disabled) + '/':
                cont = True
                print '|    ' + disabled + ' is disabled'
                if 'all' == compile_type:
                    print '|    ...this module will be compiled, but not linked!\n|'
                elif 'enabled' == compile_type:
                    print '|    ...this module will not be compiled!\n|'
                else:
                    print '|    ...ignoring this directory!\n|'
        if True == cont:
            continue
        
        try:
            path = os.path.join(current_module, MODULE_INFO_FILE)
            (name, info) = parse_module_info(path, applications)
            print '|    found module: ' + name,
            print '(version ' + info['version'] + ')'
            module_info[name] = info
        except:
            print '|\n|    WARNING parsing of module info file',
            print '\'' + path + '\' failed!'
            print '|    ...ignoring this directory\n|'
    
    return module_info

# Checks the module_info data structure for missing dependencies and conflicts
# between modules. Returns a  
def process_module_info(module_info):
    
    includes = {}
    init_functions = {}
    num_modules = {}
    
    for current_module in module_info.keys():
        # Check for dependencies
        for require in module_info[current_module]['requires']:
            if False == (require['name'] in module_info.keys()):
                print '|\n|    ERROR ' + current_module,
                print 'requires module ' + require['name']
                sys.exit('|    ...abort current run. Please check module configuration\n|')
            else:
                req_version = module_info[require['name']]['version']
                
                if require.has_key('minversion') and req_version < require['minversion']:
                    print '|\n|    ERROR ' + current_module + ' requires module',
                    print require['name'] + ' at least in version ' + require['minversion']
                    sys.exit('|    ...abort current run. Please check module configuration\n|')
                if require.has_key('maxversion') and req_version > require['maxversion']:
                    print '|\n|    ERROR ' + current_module + ' requires module',
                    print require['name'] + ' at most in version ' + require['maxversion']
                    sys.exit('|    ...abort current run. Please check module configuration\n|')
                
        # Check for conflicts
        for conflict in module_info[current_module]['conflicts']:
            if conflict['name'] in module_info.keys():
                con_version = module_info[conflict['name']]['version']
                
                if False == ((conflict.has_key('minversion') and 
                              con_version < conflict['minversion']) or 
                             (conflict.has_key('maxversion') and 
                              con_version > conflict['maxversion'])):
                    print '|    ERROR ' + current_module + ' conflicts with module ' + conflict['name'] + ' (version ' + con_version + ')'
                    sys.exit('|    ...abort current run. Please check module configuration\n|')

    for current_module in module_info.keys():
        for app_name in module_info[current_module]['application'].keys():
            # Build includes
            if includes.has_key(app_name):
                tmp = includes.pop(app_name)
            else:
                tmp = []
        
            tmp.append(module_info[current_module]['application'][app_name]['header_file'])
            includes[app_name] = tmp
            
            # Build init_functions
            if init_functions.has_key(app_name):
                tmp = init_functions.pop(app_name)
            else:
                tmp = []
        
            tmp.append(module_info[current_module]['application'][app_name]['init_function'])
            init_functions[app_name] = tmp
   
    return (includes, init_functions)

# Creates a C header file with the given filename an the needed includes,
# the number of init functions per application and an array of function
# pointers for each application
def create_header_files(output_dir, suffix, applications, includes, init_functions):
    
    for current_app in applications.keys():
        
        hdr_file_path = os.path.join(output_dir, current_app + suffix)
        hdr_file = open(hdr_file_path, 'w')
        
        app_string = 'HIP_' + current_app.upper() + '_MODULES_H'
        
        hdr_file.write('#ifndef ' + app_string + '\n')
        hdr_file.write('#define ' + app_string + '\n')
        
        if includes.has_key(current_app) and init_functions.has_key(current_app):
        
            num_modules = str(len(init_functions[current_app]));
            for current in includes[current_app]:
                hdr_file.write('\n#include \"' + current + '\"')
                
            hdr_file.write('\n\ntypedef int (*pt2Function)(void);\n')
            hdr_file.write('\nconst int num_modules_' + current_app + ' = ')
            hdr_file.write(num_modules + ';')
                
            hdr_file.write('\n\nstatic const pt2Function ' + current_app)
            hdr_file.write('_init_functions[' + num_modules + '] = {')
    
            first_loop = True
            for function in init_functions[current_app]:
                if first_loop != True:
                    hdr_file.write(', ')
                hdr_file.write('&' + function)
                first_loop = False
            hdr_file.write('};')
        else:
            hdr_file.write('\n\ntypedef int (*pt2Function)(void);\n')
            hdr_file.write('\nconst int num_modules_' + current_app + ' = 0;')
                
            hdr_file.write('\n\nstatic const pt2Function ' + current_app)
            hdr_file.write('_init_functions[0] = {}')
    
        hdr_file.write('\n\n#endif /* ' + app_string + ' */')
        hdr_file.close()
        
        print '|    created file: ' + hdr_file_path

# Creates a file at file_path and includes a Makefile.am from all given modules
# sub directories.        
def create_makefile_modules(file_path,
                            module_info,
                            disabled_modules,
                            applications,
                            compile_type):

    makefile_modules = open(file_path, 'w')
    
    enabled_modules = module_info.keys()
    all_modules = enabled_modules + list(disabled_modules)
    
    if 'all' == compile_type:
        compile_modules = all_modules
    elif 'enabled' == compile_type:
        compile_modules = enabled_modules
    else:
        print '|\n|    ERROR compile_type \'' + compile_type + '\' is unknown.'
        sys.exit('|    ...abort current run. Please check project configuration\n|')
    
    # Include compile statements from module Makefile.am's 
    for current in compile_modules:
        path = os.path.join(MODULES_DIR, current, 'Makefile.am')
        makefile_modules.write('include ' + path + '\n')
        
    makefile_modules.write('\n')
    # Write linker commands to Makefile.modules
    for current_module in enabled_modules:
        for current_app in module_info[current_module]['application']:
            linkcommand = module_info[current_module]['application'][current_app]['linkcommand']
            makefile_modules.write(linkcommand + '\n')
    
    makefile_modules.close() 
    print '|    created file: ' + file_path


### Main program ###

(applications, compile_type, disabled_modules) = parse_info_file(INFO_FILE_PATH)

module_info  = read_module_info(MODULES_DIR, disabled_modules, applications, compile_type)

(includes, init_functions) = process_module_info(module_info)

create_header_files(HEADER_FILE_DIR, HEADER_FILE_SUFFIX, applications, includes, init_functions)

create_makefile_modules('Makefile.modules', module_info, disabled_modules, applications, compile_type)
