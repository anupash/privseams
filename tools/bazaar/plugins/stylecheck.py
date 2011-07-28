#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# Copyright (c) 2010-2011 Aalto University and RWTH Aachen University.
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#

#
# Contributors:
# Stefan Götz <stefan.goetz@web.de>
#

_stylecheck_tutorial = """
Bazaar plugin that prevents commits containing code style violations.

About
-----
This plugin runs the code beautifier 'uncrustify' on all files supported by
uncrustify and that are added or modified by a commit. If a file to commit and
the output of uncrustify differ, these differences are printed along with a
final summary of all non-conforming files and the commit is aborted. This hook
expects to find an uncrustify configuration file in the top-level directory of
the repository tree. It first looks for a file named '.uncrustify-<version>.cfg'
where <version> is the version of the locally installed uncrustify binary
available in PATH. If this version-specific configuration file is not found,
this hook looks for a file named '.uncrustify.cfg'. If no such file can be
found, an error message is printed, but the commit is not aborted and may
proceed normally.

Installation
------------
Copy this file into the bazaar plugin directory (usually .bazaar/plugins/ in
your home directory) or add the directory this file resides in to the
environment variable BZR_PLUGIN_PATH (export BZR_PLUGIN_PATH="<dir>") before
running 'bzr commit'. Make sure that the programs uncrustify, diff and patch
are available - this hook depends on them. If this hook cannot find a necessary
prerequisite for the style checks, it prints an error message and aborts the
commit. To disable the hook in such a case, remove this file from the bazaar
plugin directory (see Installation above).

Usage
-----
This hook is called automatically when running the command 'bzr commit' after
the commit message has been provided. If all added or modified files pass the
uncrustify check or none of the files are supported by uncrustify, the commit
continues normally. If the check fails due to a style violation, those
violations are printed as a unified diff between the new code and its
uncrustified version on standard output and the commit fails. Actual style
violations found this way should be fixed and the updated code should be
re-committed. If the commit is aborted because uncrustify incorrectly reports a
style violation in correctly formatted code, the uncrustify configuration file
should be adapted accordingly. If for some reason the commit should be forced
despite style violations, the bazaar commit option --no-plugins skips the style
check and allows the commit to succeed.

"""

version_info = (0, 2, 0, 'dev', 0)
plugin_name = 'stylecheck'

from bzrlib import branch, help_topics
import bzrlib
import subprocess
import os.path
import sys
import tempfile
import re


def get_local_file_name(branch, file_name):
    """Determine the absolute path of the file in a local Bazaar working branch.

    Arguments:
    branch -- an instance of bzrlib's Branch representing a local working
    branch. file_name is resolved relative to the base location of branch.
    file_name -- a string containing the relative path of a file in the file
    tree of branch.

    This function returns a string that contains the absolute path of the
    specified file. This file is the actual on-disk working copy and can be
    accessed and modified. If file_name does not exist in branch or the
    corresponding local file cannot be found, a RuntimeError is raised.

    """
    base = branch.base
    if base.startswith('file://'):
        base = base[7:]
    local_file_name = os.path.join(base, file_name)
    if os.path.exists(local_file_name):
        return local_file_name
    else:
        raise RuntimeError("The file '%s' in branch '%s' could not be found at \
'%s' as expected!" % (file_name, branch, local_file_name))


class Beautifier(object):
    """A common base class for locally installed source code beautification
    tools.

    This class allows to check whether a specific code beautifier can be
    expected to work and it wraps the tool-specific handling of configuration
    files and command lines.

    """
    def __init__(self):
        """Creates and initializes a Beautifier object and its attributes.

        If the initialization fails, e.g., because a tool is not available,
        an exception is raised.

        """
        self.cfg = None
        self.local_cfg = None

    def supports(self, file_name):
        """Return whether this tool supports the specified file."""
        raise NotImplementedError()

    def get_command(self, local_file_name):
        """Retrieve a command line that, when executed, provides the beautified
        version of a file.

        Arguments:
        local_file_name -- a local file to run the tool on. The returned
        command line is guaranteed to not modify this file.

        This function returns a command line that can be executed as a shell
        command. The command line runs the tool such that the beautified
        version of local_file_name is available on stdout.

        """
        raise NotImplementedError()


class Uncrustify(Beautifier):
    """Represents the locally installed version of uncrustify and its
    configuration data.

    """
    def __init__(self, branch, tree):
        """Creates and initializes an Uncrustify object and its attributes.

        Arguments:
        branch -- a bzrlib Branch instance representing the repository this
        commit hook applies to.
        tree -- a bzrlib Tree instance representing the future repository
        contents after the commit.

        If the initialization fails, e.g. because the uncrustify binary or
        other required resources are not available, a RuntimeError or
        CalledProcessError is raised.

        """
        super(Uncrustify, self).__init__()
        self.version = self._get_version()
        self.cfg = self._get_cfg(tree)
        self.local_cfg = get_local_file_name(branch, file_name = self.cfg)
        self._check_prerequisites([self.local_cfg])

    def supports(self, file_name):
        """Return whether this tool supports the specified file."""
        # check whether the given file is supported by uncrustify
        (root, ext) = os.path.splitext(file_name)
        return ext.lower() in ['.c', '.cpp', '.d', '.cs', '.vala', '.java',
                               '.pawn', '.p', '.sma', '.inl', '.h', '.cxx',
                               '.hpp', '.hxx', '.cc', '.di', '.m', '.mm',
                               '.sqc', '.es' ]

    def get_command(self, local_file_name):
        """Retrieve a command line that, when executed, provides the beautified
        version of a file.

        Arguments:
        local_file_name -- a local file to run uncrustify on. The returned
        command line is guaranteed to not modify this file.

        This function returns a command line that can be executed as a shell
        command. The command line runs uncrustify such that the beautified
        version of local_file_name is available on stdout.

        """
        return "uncrustify -c '%s' -f '%s'" % (self.local_cfg, local_file_name)

    def _check_prerequisites(self, files):
        """Check whether the necessary tools and files are available to run
        uncrustify and perform the code style check.

        Arguments:
        files -- files that must be accessible on the host file system for the
        code style check to work.

        If the runtime environment lacks a required feature, a
        RuntimeError is raised that specifies the missing component.

        """
        for file_name in files:
            if not os.path.exists(file_name):
                raise RuntimeError("The file '%s' required for code style \
checking cannot be found" % (file_name))
        fd = file('/dev/null', 'w')
        for binary in [ 'uncrustify', 'diff' ]:
            if subprocess.call(['which', binary], stdout = fd):
                fd.close()
                raise RuntimeError("The binary '%s' required for code style \
checking cannot be found" % (binary))
        fd.close()

    def _get_version(self):
        """Retrieve the version of uncrustify installed on the local system.

        If the uncrustify version can be determined successfully, this function
        returns a string of the format '0.57'.
        If the version of uncrustify cannot be determined, a RuntimeError or
        CalledProcessError is raised.

        """
        cmd = ['uncrustify', '--version']
        process = subprocess.Popen(cmd, stdout = subprocess.PIPE)
        (output, _) = process.communicate()
        if process.wait() == 0:
            match = re.search('[0-9.]+', output)
            if match:
                return match.group(0)
            else:
                raise RuntimeError("Unable find version string in uncrustify \
output '%s'" % (command_output))
        else:
            raise CalledProcessError("The command '%s' exited with return code \
%d" % (" ".join(cmd), process.returncode))

    def _get_cfg(self, tree):
        """In a Bazaar repository tree, look for the uncrustify configuration
        file that best matches the uncrustify version.

        Arguments:
        tree -- the Bazaar repository tree to walk to find the configuration
        file in.

        If a configuration file is found, its path name in the tree is returned
        as a string.
        If no configuration file is found, a ValueError is raised.

        """
        # first try to use the config file that has the version of uncrustify
        # as a suffix to get a better version match.
        # TODO: improve this so that the latest configuration not newer than
        # uncrustify is used.
        names = [".uncrustify-%s.cfg" % (self.version),
                 '.uncrustify.cfg']
        for name in names:
            if tree.has_filename(name):
                return name
        raise ValueError("Unable to find an uncrustify configuration file in \
this repository")


class Beautification(object):
    """Represents the results of running a code beautifier tool (such as
    uncrustify) on a certain set of files from a Bazaar tree.

    An instance of this class holds the tree, a subset of its files, and the
    tool to use.
    It can then be used to run the beautifier tool, access the changes it
    would make, and apply the changes to the original files on disk.

    """
    def __init__(self, branch, tree, files, tool = None):
        """Create a Beautification object that holds information on a code
        beautification run.

        Arguments:
        branch -- a bzrlib Branch instance representing the working branch
        containing tree.
        tree -- the Bazaar tree to retrieve the files to beautify from. This is
        expected to be a local tree with the given files being accessible on the
        file system.
        files -- a list of strings, each containing the relative path name of a
        file in the tree. The code beautification is only applied to those files
        (or rather the subset supported by the beautification tool).
        tool -- the beautification tool to use. If not specified here, it needs
        to be supplied to the run() function.

        When a Beautification object is no longer used, its cleanup() function
        should be called to release all associated resources.

        """
        self._branch = branch
        self._tree = tree
        self._files = files
        self._tool = tool
        self._diff_file = None

    def run(self, tool = None):
        """Retrieve the results of running a code beautification tool on the
        file set of this Beautification object.

        Arguments:
        tool -- the beautification tool to use. If no tool object is supplied to
        both the contstructor and this function, a RuntimeError is raised. If a
        tool object is supplied to both the constructor and this function, the
        one specified here takes precedence.

        This function returns a file object which contains the differences
        between the original files and their beautified version. The file is
        deleted automatically from the file system when the file object is
        closed. If there are no differences, this function returns None.

        """
        tl = tool or self._tool
        errors = []
        violations = []
        diff_file = tempfile.NamedTemporaryFile(prefix = plugin_name + "-diff-")
        for tree_file_name in [f for f in self._files if tl.supports(f)]:
            try:
                local_file_name = get_local_file_name(self._branch,
                                                      tree_file_name)
                # are the file to commit and its uncrustified version different?
                p = subprocess.Popen("%s | diff -u '%s' -" %
                                     (tl.get_command(local_file_name),
                                      local_file_name), shell=True,
                                      stdout = diff_file)
                if p.wait() != 0:
                    violations.append(tree_file_name)
            except Exception as e:
                errors.append("The style check for file '%s' failed: %s" %
                                   (file_name, str(e)))

        diff_file.seek(0)
        if violations:
            self._diff_file = diff_file
        else:
            diff_file.close()

        if errors:
            print "\n".join(errors)

        return self._diff_file

    def apply_to_branch(self):
        """Apply a code beautification to the local Bazaar branch.

        While the run() function only analyzes the differences between the
        original code and its beautified version, this function applies those
        differences (i.e., the beautification) to the on-disk files in the
        specified Bazaar branch.

        If this function is called before the run() function or if the run()
        function returned None, a ValueError is raised.
        If applying the beautification fails, a CalledProcessError is raised.

        """
        if self._diff_file:
            subprocess.check_call(['patch', '-p0', '-i', self._diff_file.name])
        else:
            raise ValueError("No style changes to apply")

    def cleanup(self):
        if self._diff_file:
            self._diff_file.close()


def get_files_to_check(tree_delta):
    """From all modifications in a commit, retrieve those files which should be
    checked for style violations.

    That is: added and modified files while ignoring meta-data changes or
    renamed files.

    The return value is a list of strings, each containing the path name of a
    file to check in the Bazaar repository tree.

    """
    # include added and modified, skip removed, renamed, and changed
    files = [path for path, file_id, kind in tree_delta.added if kind == 'file']
    files.extend([path for (path, file_id, kind, text_modified, _) in
        tree_delta.modified if kind == 'file'])
    return files


def get_commit_message(local, master, revid):
    """Returns the commit message of a branch revision."""
    branch = local or master
    revision = branch.repository.get_revision(revid)
    return revision.message


def pre_commit_hook(local, master, old_revno, old_revid, future_revno,
                    future_revid, tree_delta, future_tree):
    """Check the code style of files to commit and abort the commit if there are
    style violations.

    This is the pre-commit hook interface of bzrlib.
    The real work is performed in the Uncrustify and Beautification classes.

    """
    try:
        uncrustify = Uncrustify(local or master, future_tree)
        beautification = Beautification(local or master, future_tree,
                                        get_files_to_check(tree_delta),
                                        uncrustify)
    except Exception as e:
        print "Cannot check code style: %s\n  To disable this pre-commit hook \
for code-style checking, remove the plugin file %s.py" % (str(e), plugin_name)
        return

    diff_file = beautification.run()
    if diff_file:
        print "\nThe following differences were found between the code to commit and the rules in '%s':\n\n%s\nThe above changes are also available in the file %s\nWould you like to apply these changes to your local branch now? [y/N] " % (uncrustify.cfg, diff_file.read(), diff_file.name),
        reply = sys.stdin.readline()
        if reply.strip() == 'y':
            beautification.apply_to_branch()
            print "Style changes successfully applied.\n"
        diff_file.close()

        # Store the commit message in a file so it can be retrieved later
        msg_file = tempfile.NamedTemporaryFile(prefix = "bzr-commit-revno-%d-" % (future_revno), delete = False)
        msg_file.write(get_commit_message(local, master, future_revid))
        msg_file.close()

        raise bzrlib.errors.BzrError("This commit has been aborted. Your original commit message (see %s) was:\n--\n%s\n--" % (msg_file.name, get_commit_message(local, master, future_revid)))


help_topics.topic_registry.register(plugin_name + '-tutorial',
                                    _stylecheck_tutorial,
                                    'How to use the plugin ' + plugin_name)

branch.Branch.hooks.install_named_hook('pre_commit', pre_commit_hook,
                                       plugin_name)

