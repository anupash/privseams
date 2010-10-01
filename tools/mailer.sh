#!/bin/sh
#
# Mailer script that notifies about commits to a BZR repo
#
# Copyright (c) 2010 Mircea Gherzan <mgherzan@gmail.com>

# path to the BZR repository
REPO=/home/$USER/src/hipl
# path to the file containing the last processed revision
LASTREV=/tmp/mailer_lastrev.txt
# buffer used to build the body of the e-mail
MAILBUF=/tmp/mailer_buffer.txt

# mailing coordinates
SENDTO=hipl-core@lists.launchpad.net
REPLYTO=hipl-core@lists.launchpad.net

#####################################################################

if [ ! -e $LASTREV ]; then
    echo File with the last revno does not exist!
    echo Please create $LASTREV
    exit 1
fi

read lastrev < $LASTREV

# from now on, working in the BZR repo
cd $REPO || exit 1

# update the repo to get the last revision
bzr up

# get the HEAD revision (the last one)
head=$(bzr revno)

# lastrev was already processed, so incrementing it
lastrev=$(($lastrev + 1))

for rev in $(seq $lastrev $head); do
    committer=$(bzr log -r $rev | head -3 | tail -1 | sed -e "s/committer: //g")
       branch=$(bzr log -r $rev | head -4 | tail -1 | sed -e "s/branch nick: //g")
    firstline=$(bzr log -r $rev | head -7 | tail -1 | sed -e "s/^ *//")

    subject="[$branch] $rev: $firstline"

    # create the body of the e-mail
    bzr log -r $rev | tail -n +7 > $MAILBUF
    echo "" >> $MAILBUF
    bzr diff -c $rev >> $MAILBUF

    # send the e-mail
    mailx -s "$subject" -Sfrom="$committer" -Sreplyto=$REPLYTO $SENDTO < $MAILBUF
done

echo $head > $LASTREV

exit 0
