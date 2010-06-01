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

"""Checking commit messages for whitelisted tags.

The plugin will reject all commits whose commit messages don't contain the following pattern:
"[taglist]", where tags is a comma-separated whitelist of tags.
The allowed tags are specified in option `tagchecker_whitelist` in the branch.conf of every branch,
the tagchecker should control.
e.g. add line
    tagchecker_whitelist = tag1,tag2,...,tagn
to the branch.conf.

To install this plug in system wide copy it into the plugins directory
of the bzrlib. You can find out the directory of the bzrlib by executing
    `` bzr version | grep bzrlib ``
This should be something like
    `` /usr/lib/python2.6/dist-packages/bzrlib ``
Then you put the plugin into
    `` /usr/lib/python2.6/dist-packages/bzrlib/plugins/tagchecker ``
That's all.

You can check the installation by executing
    `` bzr plugins ``
(tagchecker plugin should be displayed with a short message)
or
    `` bzr hooks ``
(pre_change_branch_tip should have an entry from tagchecker now)
"""


if __name__ != 'bzrlib.plugins.tagchecker':
    raise ImportError('The email plugin must be installed as'
                      ' bzrlib.plugins.tagchecker not %s'
                      % __name__)


# These three are used during import: No point lazy_importing them.
from bzrlib import errors
from bzrlib.branch import Branch
from bzrlib.lazy_import import lazy_import

# lazy_import emailer so that it doesn't get loaded if it isn't used
lazy_import(globals(), """\
from bzrlib.plugins.tagchecker import tagchecker as _tagchecker
""")

def pre_change_branch_tip_hook(params):
    """This hook will be called on the server's side before a change."""
    # (branch, old_revno, new_revno, old_revid, new_revid)
    _tagchecker.TagChecker(params).check()

def install_hook(bzr_hook, callback, name):
    """Install the given hook with the given name """
    if bzr_hook in Branch.hooks:
        install_named_hook = getattr(Branch.hooks, 'install_named_hook', None)
        if install_named_hook is not None:
            install_named_hook(bzr_hook, callback, name)
        else:
            Branch.hooks.install_hook(bzr_hook, callback)
            if getattr(Branch.hooks, 'name_hook', None) is not None:
                Branch.hooks.name_hook(callback, name)
    else:
        raise errors.BzrError("Bazaar version does not support " + bzr_hook + " hooks.")

# Install all hooks here
def install_hooks():
    """Install pre_change_branch_tip hook """
    install_hook('pre_change_branch_tip', pre_change_branch_tip_hook, 'bzr tagchecker')

def test_suite():
    return


# setup the email plugin with > 0.15 hooks.
try:
    install_hooks()
    use_legacy = False
except AttributeError:
    # bzr < 0.15 - no Branch.hooks
    use_legacy = True
except errors.UnknownHook:
    # bzr 0.15 dev before post_commit was added
    use_legacy = True
