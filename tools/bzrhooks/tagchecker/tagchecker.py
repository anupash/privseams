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

class TagChecker(object):

    def __init__(self, params, local_branch=None):
        """ The only thing we need is the revision and the config"""

        self.config = params.branch.get_config()

        if (local_branch is not None and local_branch.repository.has_revision(self.new_rev_id)):
            repository = local_branch.repository
        else:
            repository = params.branch.repository

        self.revision = repository.get_revision(params.new_revid)

    def _errormessage(self, tag_list, reason):
        res = ""
        if reason == "notagfound":
            res += "\n" \
                "Commit was rejected because the commit-message did not contain any tag \n" \
                "The commit-message should contain at least one tag from the following list: \n"

            # Append list of allowed tags
            for tag in tag_list:
                res += "    - " + tag + "\n"

        elif reason == "wrongformat":
            res += "\n" \
                "Commit was rejected because tags were not given in the right format \n" \
                "Tags should appear immediately at the beginning of the commit message enclosed in brackets.\n" \
                "F.e. [tag1, tag2, tag3, ... ] logsummary ... logmessage...\n" \

        # Append the old log-message
        res += "\n" \
            "You entered the following log-message:\n"
        if not self.revision.message:
            res += "  (no log message found)\n"
        else:
            res += self.revision.message.rstrip('\r\n')
            res += "\n\n"

        return res

    def check(self):
        """ Check if the commit message begins with at
            least one tag from a whitelist, given by
            commit_notification_tags option. """

        # This is the tag white list
        # Each commit message should begin with at least one of those tags
        # tag_white_list = ["test","bugfix","docu"]
        tag_white_list = self.config.get_user_option('tagchecker_whitelist')

        # No tag checking...
        if tag_white_list is None:
            return

        # Get commit message
        message = self.revision.message

        # We assume that tags are enclosed in brackets
        tags_start = message.find('[')
        tags_end = message.find(']')
        if tags_start != 0 or tags_end == -1:
            raise errors.TipChangeRejected(self._errormessage(tag_white_list, "wrongformat"))

        # Check for each tag from the white list if it appears in the message tag area
        # and return on first match
        for tag in tag_white_list:
            if message.find(tag, tags_start, tags_end) != -1:
                return

        # No match found
        raise errors.TipChangeRejected(self._errormessage(tag_white_list, "notagfound"))
