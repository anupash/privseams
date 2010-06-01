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

import errno
import subprocess
import customlogformatter as clf
import datetime
import time
import sys
import warnings
import codecs

from bzrlib import (
    errors,
    revision as _mod_revision,
    log
    )

class EmailSender(object):
    """An email message sender."""

    server_mode = False

    def __init__(self, params, op, local_branch=None):
        # Extract useful information from params
        self.config = params.branch.get_config()
        self.branch = params.branch
        self.new_revid = params.new_revid
        self.old_revid = params.old_revid
        self.new_revno = params.new_revno
        self.old_revno = params.old_revno
        if (local_branch is not None and local_branch.repository.has_revision(self.new_rev_id)):
            self.repository = local_branch.repository
        else:
            self.repository = self.branch.repository

        # Which hook was exectued
        self.op = op

        # Server mode?
        self.server_mode = EmailSender.server_mode

        # Which charset
        self.charset = 'utf-8'

    def setup_revision_and_revno(self):
        """Get the revision and revision number from the branch."""
        if self.uncommit:
            # We want to notify about the revision that is being uncommited
            self.revision = self.repository.get_revision(self.old_revid)
            tmp = self.new_revid
            self.new_revid = self.old_revid
            self.old_revid = tmp
            tmp = self.new_revno
            self.new_revno = self.old_revno
            self.old_revno = tmp
        else:
            self.revision = self.repository.get_revision(self.new_revid)

    def get_merge_info(self):
        """ Display some additional information if this revision is a merge """

        # Get new working tree
        tree_new = self.repository.revision_tree(self.new_revid)

        # Get parent ids.. if this is a merge there are more than one.
        parent_ids = self.repository.get_revision(self.new_revid).parent_ids
        if len(parent_ids) <= 1:
            return ""

        # Create merge information
        res = "Merge from following parent revisions and branches:\n"
        for merge in parent_ids:
            try:
                rev = self.repository.get_revisions([merge])[0]
                res += "  - " + rev.properties.get('branch-nick', '(branch nick n/a)') +"\t  (parent-id: " + merge + ")    \n"
            except errors.NoSuchRevision:
                # If we are missing a revision, just print out the revision id
                res += ' (ghost) ' + merge + '\n'
                continue

        return res + "\n"

    def body(self):
        """Create the email body"""
        from bzrlib import log

        # Determine start and end revision to display
        rev1 = rev2 = self.new_revno
        if rev1 == 0:
            rev1 = None
            rev2 = None

        # We must use StringIO.StringIO because we want a Unicode string that
        # we can pass to send_email and have that do the proper encoding.
        from StringIO import StringIO
        outf = StringIO()
        try:
            enc, dec, reader, writer = codecs.lookup(self.charset)
            writebuffer = writer(outf, 'replace')
        except LookupError:
            warnings.warn("Failed to lookup " + charset + "-codec. You might encounter further errors regarding encoding..")
            writebuffer = outf

        try:
            # Use custom log formatter, which displays logrevisions in pisa-style...
            lf = clf.CustomLogFormatter(show_ids=False, to_file=writebuffer)

            # Let the show_log code do all the work
            # set verbose = True to provide a treedelta
            log.show_log(self.branch, lf, start_revision=rev1, end_revision=rev2, verbose=True, show_diff=True)

            # This could be a merge, too...
            merge_info = self.get_merge_info()
        except UnicodeError:
            warnings.warn("There was a unicode error...")

        # If this an uncommit, write a short note
        additional_info = ""
        if self.uncommit:
            additional_info = " ------- Log of revision UNCOMMITTED on " + time.strftime("%y/%m/%d at %H:%M:%S") + " ------- \n \n"

        try:
            logmessage = outf.getvalue()
        except UnicodeError:
            logmessage = "(empty due to UnicodeDecodeError) \n"
            warnings.warn("Error while creating logmessage. Notification with empty revisionlog will be sent!")

        return additional_info + logmessage + merge_info

    def to_address(self):
        """What is the address the mail should go to."""
        return self.config.get_user_option('commit_notification_to')

    def from_address(self):
        """What address should I send from."""
        # On default the commiter is the sender,
        # overwrite this by setting post_commit_sender in bazaar.conf or branch.conf
        result = self.config.get_user_option('commit_notification_sender')
        if result is None:
            result = self.repository.get_revision(self.new_revid).committer

        return result

    def send(self):
        """Send the email."""
        self.branch.lock_read()
        self.repository.lock_read()
        try:
            self._send_using_smtplib()
        finally:
            self.repository.unlock()
            self.branch.unlock()

    def _send_using_smtplib(self):
        """Use python's smtplib to send the email."""
        import smtplib
        from email.mime.text import MIMEText


        # Encode message body
        try:
            body = self.body().encode(self.charset)
        except UnicodeEncodeError:
            warnings.warn("Could not encode email body. No notification sent!")
            return

        # Create the email
        try:
            message = MIMEText(body, 'plain', self.charset)
        except TypeError:
            warnings.warn("Could not create email. No notification sent!")
            return

        message['Subject'] = self.subject()
        message['From'] = self.from_address()
        message['To'] = self.to_address()

        # Send the message via our own SMTP server, but don't include the
        # envelope header.
        try:
            server = smtplib.SMTP('localhost')
        except:
            warnings.warn("Could not connect to local mailserver. No notification sent!")
            return

        # Send the mail
        server.sendmail(self.from_address(), self.to_address(), message.as_string())
        server.quit()

    def should_send(self):
        """Determine if a notification should be sent at the present point.

           Only send if running as server.

           If called from pre_change_branch_tip hook we only want to send a mail if this is an uncommit.
           If called from post_change_branch_tip hook we want to send a mail if this is a commit or merge.
        """

        # Determine whether this is an uncommit and set up revision, revision ids and revision numbers accordingly
        if (self.new_revno - self.old_revno) > 0:
            self.uncommit = False
        else:
            self.uncommit = True
        self.setup_revision_and_revno()

        # Server mode is not running as the server_started hook doesn't get fired,
        # so this feature is disabled
        # A client should not send mails, as this is supposed to run on a server.
        # if not self.server_mode:
        #    return False

        # If pre_change_branch_tip hook is exectued on something not an uncommit
        if (self.op == 'pre_change' and not self.uncommit):
            return False

        # If post_change_branch_tip hook is exectued on an uncommit
        if (self.op == 'post_change' and self.uncommit):
            return False

        # Only send if to- and from-address is known
        # Don't set at least one of these in order to disable email-notification.
        return bool(self.to_address() and self.from_address())

    def send_maybe(self):
        if self.should_send():
            self.send()


    def subject(self):
        """Create the subject of the email notification"""
        branch_nick = self.revision.properties.get('branch-nick','(branch nick n/a)')

        additional_info = ""
        if self.uncommit:
            additional_info = "[UNCOMMIT]"

        return ("[" + branch_nick + "] Rev %d: %s %s" %
                (self.new_revno,
                 self.revision.get_summary(),
                 additional_info))
