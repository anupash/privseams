#!/usr/bin/python
import getopt, glob, os, sys, xml.dom.minidom

### Constants ###
APPLICATION_TAG_NAME  = 'application'
APPLICATION_ATTR_NAME = 'name'
APPLICATION_PATH_NAME = 'path'

MODULES_DIR      = 'modules'
MODULE_INFO_FILE = 'module_info.xml'

HEADER_FILE_DIR    = MODULES_DIR
HEADER_FILE_SUFFIX = '_modules.h'

### Functions ###

# Parses the XML document at 'path' and returns a dictionary with module info
def parse_module_info(path, applications, required_modules):

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
            required_modules.add(current_req['name'])

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
        applications.add(name)
        app_info['header_file'] = str(current_app.attributes['header_file'].value)
        app_info['init_function'] = str(current_app.attributes['init_function'].value)
        module_info['application'][name] = app_info

    return (applications, module_name, module_info, required_modules)

# Tries to read the XML configuration files for all sub-folders in the given
# directory and returns a dictionary containing the module information
def read_module_info(MODULES_DIR, disabled_modules):

    # Initialize output variable
    module_info = {}
    required_modules = set()
    applications = set()

    # Iterate through all sub directories in MODULES_DIR
    for current_module in glob.glob(MODULES_DIR + '/*/'):
        cont = False
        print '|    found module: ' + current_module
        # Check if current_module is disabled
        for disabled in disabled_modules:
            if current_module == os.path.join(MODULES_DIR, disabled) + '/':
                cont = True
                print '|    state:        ' + 'DISABLED'
                print '|    (ignoring this directory)\n|'
        if True == cont:
            continue

        try:
            path = os.path.join(current_module, MODULE_INFO_FILE)
            (applications, module_name, info, required_modules) = parse_module_info(path,
                                                                       applications,
                                                                       required_modules)
            print '|    state:        ' + 'ENABLED'
            print '|    version:      ' + info['version'] + '\n|'
            module_info[module_name] = info
        except:
            print '|\n|    WARNING parsing of module info file',
            print '\'' + path + '\' failed!'
            print '|    ...ignoring this directory\n|'

    return (applications, module_info, required_modules)

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
def create_header_files(output_dir, suffix, applications, includes, init_functions, enabled_modules, required_modules):

    if False == os.path.isdir(output_dir):
        os.mkdir(output_dir)

    for current_app in applications:

        hdr_file_path = os.path.join(output_dir, current_app + suffix)

        try:
            hdr_file = open(hdr_file_path, 'w')
            try:
                app_string = 'HIP_' + current_app.upper() + '_MODULES_H'

                hdr_file.write('#ifndef ' + app_string + '\n')
                hdr_file.write('#define ' + app_string + '\n')

                if includes.has_key(current_app) and init_functions.has_key(current_app):
                    num_modules = str(len(init_functions[current_app]));
                    for current in includes[current_app]:
                        hdr_file.write('\n#include \"' + current + '\"')

                    hdr_file.write('\n\ntypedef int (*pt2Function)(void);\n')
                    hdr_file.write('\nconst int num_modules_' + current_app + ' = ')
                    hdr_file.write(num_modules + ';\n')
                    hdr_file.write('\nconst int num_required_modules_' + current_app + ' = ')
                    hdr_file.write(str(len(required_modules)) + ';\n')
                    hdr_file.write('\nconst char *modules_' + current_app + '[')
                    hdr_file.write(num_modules + '] = {')
                    first_loop = True
                    for module in enabled_modules:
                        if first_loop != True:
                            hdr_file.write(', ')
                        hdr_file.write('"' + module + '"')
                        first_loop = False
                    hdr_file.write('};')
                    hdr_file.write('\n\nconst char *required_modules_' + current_app + '[')
                    hdr_file.write(str(len(required_modules)) + '] = {')
                    first_loop = True
                    for module in required_modules:
                        if first_loop != True:
                            hdr_file.write(', ')
                        hdr_file.write('"' + module + '"')
                        first_loop = False
                    hdr_file.write('};')

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
                    hdr_file.write('\n\nconst char *modules_' + current_app)
                    hdr_file.write('[0] = {};')
                    hdr_file.write('\nconst int num_required_modules_')
                    hdr_file.write(current_app + ' = 0;')
                    hdr_file.write('\n\nconst char *required_modules_')
                    hdr_file.write(current_app + '[0] = {};')
                    hdr_file.write('\n\nstatic const pt2Function ' + current_app)
                    hdr_file.write('_init_functions[0] = {};')

                hdr_file.write('\n\n#endif /* ' + app_string + ' */\n')
                print '|    created file: ' + hdr_file_path
            finally:
                hdr_file.close()
        except IOError:
            sys.exit('Error on creating header files')

# Creates a file at file_path and includes a Makefile.am from all given modules
# sub directories.
def create_makefile_modules(srcdir,
                            module_info,
                            disabled_modules):

    file_path = 'Makefile.modules'
    makefile_modules = open(file_path, 'w')

    # Include Makefile.am's from modules
    for current in module_info.keys():
        path = os.path.join(srcdir, MODULES_DIR, current, 'Makefile.am')
        makefile_modules.write('include ' + path + '\n')

    makefile_modules.write('\n')
    makefile_modules.close()
    print '|    created file: ' + file_path

### Main program ###
def main():
    srcdir = None
    disabled_modules = None

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   "s:d:",
                                   ["srcdir=", "disabled_modules="])
    except getopt.GetoptError, err:
        print str(err)
        sys.exit(2)
    for o, a in opts:
        if o in ("-s", "--srcdir"):
            srcdir = a
        elif o in ("-d", "--disabled_modules"):
            disabled_modules = a
        else:
            assert False, "unhandled option"

    if disabled_modules:
        disabled_modules = disabled_modules.rsplit(',')

    (applications, module_info, required_modules) = read_module_info(os.path.join(srcdir, MODULES_DIR),
                                                                     disabled_modules)

    (includes, init_functions) = process_module_info(module_info)

    create_header_files(HEADER_FILE_DIR,
                        HEADER_FILE_SUFFIX,
                        applications,
                        includes,
                        init_functions,
                        module_info.keys(),
                        required_modules)

    create_makefile_modules(srcdir,
                            module_info,
                            disabled_modules)

if __name__ == "__main__":
    main()
