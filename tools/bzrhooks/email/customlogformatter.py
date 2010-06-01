from bzrlib import log, builtins, status
import codecs

""" A custom built subclass of log.LogFormatter.
    Displays log of newly committed revisions in pisa style. """
class CustomLogFormatter(log.LogFormatter):

    supports_merge_revisions = True
    preferred_levels = 1
    supports_delta = True
    supports_tags = True
    supports_diff = True

    def log_revision(self, revision):
        import time

        charset = 'utf-8'

        """Log a revision, either merged or not."""
        indent = u'    ' * revision.merge_depth
        to_file = self.to_file

        # Write author / commiter
        # Only commiters are relevant for email-notification,
        # authors are omitted.
        try:
            unicodestr = revision.rev.committer.decode(charset, 'replace')
        except UnicodeError:
            unicodestr = u"n/a due to unicode issues"
        to_file.write(unicode(indent + 'Committer: %s\n' % (unicodestr,)))

        # Write date
        try:
        #    date_str = osutils.format_date(revision.rev.timestamp, revision.rev.timezone or 0, self.show_timezone, date_fmt)
            unicodestr = time.strftime("%d/%m/%Y at %H:%M:%S").decode(charset, 'replace')
        except UnicodeError:
            unicodestr = u"n/a due to unicode issues"
        to_file.write(unicode(indent + 'Date: %s\n' % (unicodestr,)))

        # Write new revision number
        if revision.revno is not None:
            try:
                unicodestr = revision.revno.decode(charset, 'replace')
            except UnicodeError:
                unicodestr = u"(n/a due to unicode issues)"
            to_file.write(unicode(indent + 'Revision: %s%s\n' % (unicodestr, self.merge_marker(revision))))

        # Always show revision id..
        #if self.show_ids:
        try:
            revidstr = revision.rev.revision_id.decode(charset, 'replace')
        except UnicodeError:
            revidstr = u"(n/a due to unicode issues)"
        to_file.write(unicode(indent + 'Revision-id: ' + revidstr))
        to_file.write('\n')

        # Write branch nick
        branch_nick = revision.rev.properties.get('branch-nick', None)
        if branch_nick is not None:
            try:
                unicodestr = branch_nick.decode(charset, 'replace')
            except UnicodeError:
                unicodestr = u"(n/a due to unicode issues)"
            to_file.write(unicode(indent + 'Branch nick: %s\n' % (unicodestr,)))
        to_file.write('\n')

        # Write log message if available
        to_file.write(indent + 'Log:\n')
        if not revision.rev.message:
            to_file.write(indent + '  (no log message available)\n')
        else:
            message = revision.rev.message.rstrip('\r\n')
            for l in message.split('\n'):
                try:
                    unicodestr = l.decode(charset, 'replace')
                except UnicodeError:
                    unicodestr = u" xx (there were encoding issues in this line) xx"
                to_file.write(indent + '  %s\n' % (unicodestr,))
        to_file.write('\n')

        # Write summary of modified files if available
        if revision.delta is not None:
            to_file.write(indent + 'Modified:\n')
            revision.delta.show(to_file, self.show_ids, indent=indent+'  ', short_status=True)
        else:
            to_file.write('   ' + "revision delta not available \n")
        to_file.write('\n')

        # Write diff, only if this is not a merge
        # If this is a merge further information will be provided by the emailer class
        if revision.diff is not None and len(revision.rev.parent_ids) <= 1:
            self.show_diff(to_file, revision.diff, indent)

    def show_diff(self, to_file, diff, indent):
        """ Show diff for files that were added and modified.
            Diffs for files that were removed are not displayed. """
        leaveout = False
        charset = 'utf-8'
        for line in diff.rstrip().split('\n'):
            try:
                unicodestr = line.decode(charset, 'replace')
            except UnicodeError:
                unicodestr = u" xx (there were encoding issues in this line) xx"

            # Not remove/renamed case, not new file
            if not leaveout and not line.startswith("==="):
                to_file.write(unicode(indent + '%s\n' % (unicodestr,)))

            # Start of new file, maybe remove/renamed case
            elif line.startswith("==="):
                parts = line.split()
                if (parts[1] == "removed" or parts[1] == "renamed") and parts[2] == "file":
                    leaveout = True
                else:
                    leaveout = False
                    to_file.write(indent + '%s\n' % (unicodestr,))

    def get_advice_separator(self):
        """Get the text separating the log from the closing advice."""
        return '-' * 60 + '\n'
