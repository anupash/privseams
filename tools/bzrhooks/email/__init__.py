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

"""Sending emails for branch changes.

To have bzr send an email you need to configure an address to send mail
to for that branch. To do this set the configuration option
    ``commit_notification_to``
in the bazaar.conf, locations.conf or branch.conf. If there is no such address
configured for a specific branch, no email-notifications will be sent when changes
in this branch occur.

The address from which the mail is sent is read from the configuration option
    ``commit_notification_sender``
If not supplied the name of the committer is taken as the originator.

The plugin sends email-notifications on commits and uncommits. Merges are
displayed in a special format.

Emails are sent using python's smtplib.

To install this plug in system wide copy it into the plugins directory
of the bzrlib. You can find out the directory of the bzrlib by executing
    `` bzr version | grep bzrlib ``
This should be something like
    `` /usr/lib/python2.6/dist-packages/bzrlib ``
Then you put the plugin into
    `` /usr/lib/python2.6/dist-packages/bzrlib/plugins/email ``
That's all.

You can check the installation by executing
    `` bzr plugins ``
(email plugin should be displayed with a short message)
or
    `` bzr hooks ``
(post_change_branch_tip, pre_change_branch_tip should have entries from email-notification now)
"""


if __name__ != 'bzrlib.plugins.email':
    raise ImportError('The email plugin must be installed as'
                      ' bzrlib.plugins.email not %s'
                      % __name__)


# These three are used during import: No point lazy_importing them.
from bzrlib import errors
from bzrlib.branch import Branch
from bzrlib.smart.server import SmartTCPServer
from bzrlib.lazy_import import lazy_import

# lazy_import emailer so that it doesn't get loaded if it isn't used
lazy_import(globals(), """\
from bzrlib.plugins.email import emailer as _emailer
""")

def server_started_hook(backing_urls, public_urls):
    """Detect if running as server to prevent clients from sending email notifications"""
    _emailer.EmailSender.server_mode = True

def post_change_branch_tip_hook(params):
    """This hook will be called on the server's side after a change."""
    # (branch, old_revno, new_revno, old_revid, new_revid)
    _emailer.EmailSender(params, op='post_change').send_maybe()

def pre_change_branch_tip_hook(params):
    """This hook will be called on the server's side before a change."""
    # (branch, old_revno, new_revno, old_revid, new_revid)
    _emailer.EmailSender(params, op='pre_change').send_maybe()

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

def install_server_hook():
    if 'server_started' in SmartTCPServer.hooks:
        install_named_hook = getattr(SmartTCPServer.hooks, 'install_named_hook', None)
        if install_named_hook is not None:
            if 'server_started' in SmartTCPServer.hooks:
                install_named_hook('server_started', server_started_hook, 'bzr email-notification')
    else:
        raise errors.BzrError("Bazaar version does not support server_started hooks.")

# Install all hooks here
def install_hooks():
    """Install post_change_branch_tip hook """
    install_hook('post_change_branch_tip', post_change_branch_tip_hook, 'bzr email-notification')

    """Install pre_change_branch_tip hook """
    install_hook('pre_change_branch_tip', pre_change_branch_tip_hook, 'bzr email-notification')

    """ Install server_started hook """
    install_server_hook()

def test_suite():
    from unittest import TestSuite
    import bzrlib.plugins.email.tests
    result = TestSuite()
    result.addTest(bzrlib.plugins.email.tests.test_suite())
    return result


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
