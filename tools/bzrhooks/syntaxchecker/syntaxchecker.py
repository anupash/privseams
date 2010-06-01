# Copyright (C) 2005, 2006, 2007 Canonical Ltd
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

from bzrlib import errors
from StringIO import StringIO
import fnmatch

class SyntaxChecker(object):

    def __init__(self, params, local_branch=None):
        """Get the revision ids, revision numbers, config and repository from the branch."""

        self.config = params.branch.get_config()
        self.branch = params.branch
        self.new_revno = params.new_revno
        self.old_revno = params.old_revno

        # Get repository for new revision
        if (local_branch is not None and local_branch.repository.has_revision(params.new_revid)):
            self.repository = local_branch.repository
        else:
            self.repository = params.branch.repository

        # Get the revision
        self.revision = self.repository.get_revision(params.new_revid)

        # Get old and new working tree
        self.new_tree =  self.repository.revision_tree(params.new_revid)
        self.old_tree = self.branch.basis_tree()

        # Initialize ignore lists
        self._init_ignore_lists()

        # Get maximal line length
        self.longline_length = self.config.get_user_option('syntax_longline_length')
        if self.longline_length is None:
            self.longline_length = 80

    def _init_ignore_list(self, user_option):
        """ Initialize the whitelist from the user option """
        list = self.config.get_user_option(user_option)

        # if no list is provided
        if list is None:
            return None

        # if only one pattern is provided
        if type(list) != type([]):
            list = [list]
        return list

    def _init_ignore_lists(self):
        """ Read the ignore for the different checks from the user config """
        self.tabs_ignorelist = self._init_ignore_list('syntax_dontcheck_tabs')
        self.whitespaces_ignorelist = self._init_ignore_list('syntax_dontcheck_whitespaces')
        self.newlines_ignorelist = self._init_ignore_list('syntax_dontcheck_newlines')
        self.longlines_ignorelist = self._init_ignore_list('syntax_dontcheck_longlines')
        self.dosbreaks_ignorelist = self._init_ignore_list('syntax_dontcheck_doslinebreaks')

    def _match(self, patterns, file):
        """ Check if file matches one of the patterns in the given list of patterns.
            If no list is provided then the file does match e.g. will be ignored"""

        # If no list was provided, file is ignored per default, e.g. matches
        if patterns is None:
            return True

        # Use unix shell-style wildcards for filename-pattern-matching
        for pattern in patterns:
            if fnmatch.fnmatch(file, pattern):
                return True

        return False

    def _get_tests(self, path):
        """ Return a list of tests to perform on the given file """
        tests = {}
        if not self._match(self.tabs_ignorelist, path):
            tests['tabs'] = self._check_tabs
        if not self._match(self.whitespaces_ignorelist, path):
            tests['whitespaces'] = self._check_trailing_whitespaces
        if not self._match(self.longlines_ignorelist, path):
            tests['longlines'] = self._check_longline
        if not self._match(self.dosbreaks_ignorelist, path):
            tests['doslinebreaks'] = self._check_dosbreaks
        return tests

    def _check_tabs(self, line):
        """ Checks if given line contains tabs """
        if '\t' in line:
            return True
        else:
            return False

    def _check_dosbreaks(self, line):
        if '\r' in line:
            return True
        else:
            return False

    def _check_trailing_whitespaces(self, line):
        """ Checks if line has trailing whitespaces.
            This is copied from text_checker plugin """
        import re
        trailing_ws_match = re.match(r'^((.*?)([\t ]*))(\r?\n)?$', line)
        if trailing_ws_match:
            return bool(trailing_ws_match.group(3))
        else:
            return False

    def _check_longline(self, line):
        """ Checks if given line is longer than 80 chars """
        if len(line) > self.longline_length:
            return True
        else:
            return False

    def _check_file(self, file_id, path):
        """ Apply tests for given file """

        # Get the lines of the file in a list
        file_lines = self.new_tree.get_file(file_id).readlines()

        # Log problems and line numbers
        problems = {'tabs' : [], 'whitespaces' : [], 'longlines' : [], 'newline' : [], 'doslinebreaks' : []}

        # Dont check empty files or files on ignorelist
        if len(file_lines) > 0 and not self._match(self.newlines_ignorelist, path):
            # Check for newline at eof
            if not file_lines[-1].endswith('\n'):
                problems['newline'] = [len(file_lines)]

        # Get further tests to perform
        tests = self._get_tests(path)

        # If there are no further tests to perform, return
        if len(tests.keys()) == 0:
            return problems

        # Keep track of line numbers where errors occur
        counter = 0

         # Perform tests on every line of every and log problems
        for line in file_lines:
            counter += 1
            for type, test in tests.iteritems():
                if test(line):
                    problems[type].append(counter)

        # Return problems
        return problems

    def check(self):
        """ Checks for each touched file in this patch if it is whitelisted,
            and if not, if it contains tabs."""

        # If this is an uncommit, there's nothing to be done
        if (self.new_revno - self.old_revno) < 0:
            return

        # Lock the trees
        self.old_tree.lock_read()
        self.new_tree.lock_read()

        try:
            # Check all modified files in new working tree
            problems = {}
            iterator = self.new_tree.iter_changes(self.old_tree)
            for (file_id, paths, changed_content, versioned, parent, name, kind, executable) in iterator:
                # paths contains two paths: the old one (index 0) and the new path (index 1) of the modified file
                # they are different if file was added, renamed or removed
                NEW_PATH = 1
                # Omit checking for files that are being removed
                if not paths[NEW_PATH] is None:
                    problems[paths[NEW_PATH]] = self._check_file(file_id, paths[NEW_PATH])

            # Construct possible error message
            fmt_string = ""
            arglist = []
            for file, problems_of_file in problems.iteritems():
                # display filename only once
                disply_filename = True
                for type, linenumbers in problems_of_file.iteritems():
                    if len(linenumbers) > 0:
                        if disply_filename:
                            fmt_string += "%12s failed check\t(type = %-15s in lines %s \n"
                            arglist += [file, type+")", str(linenumbers)]
                            disply_filename = False
                        else:
                            fmt_string += "\t\t\t\t(type = %-15s in lines %s \n"
                            arglist += [type+")", str(linenumbers)]

            # Report the errors if there were any
            errormessage = str(fmt_string % tuple(arglist))
            if errormessage != "":
                # Append the old log-message
                errormessage += "\nYou entered the following log-message:\n"
                if not self.revision.message:
                    errormessage += "  (no log message available)\n"
                else:
                    errormessage += self.revision.message.rstrip('\r\n')
                errormessage += "\n\n"

                # Report the errors
                raise errors.TipChangeRejected("\nThe commit was rejected, because there were errors.\n" + errormessage)

        finally:
            self.old_tree.unlock()
            self.new_tree.unlock()
