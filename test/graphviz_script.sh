#!/bin/bash
################################################################################
#
# Script to grep and clean the grep outputs and then reformats it to a dot
# language representation of the graph them for graphviz
#
# Calls the cleaning after grepping and draws the fig afterwards
#
# Author: Samu Varjonen
#
# NOTE: see man grapviz for more information
#
################################################################################

echo "Starting script by gathering grep info on includes"

grep "#include" ../*/*.h > /tmp/grep_results.txt
#grep "#include" ..*/*.c >> /tmp/grep_results.txt

python cleanincludesforgraph.py

#dot out.txt -Tfig -o gout.fig
neato out.txt -Tfig -o gout.fig
#fdp out.txt -Tfig -o gout.fig
#circo out.txt -Tfig -o gout.fig
#twopi out.txt -Tfig -o gout.fig

echo "Stopped working on the file and the fig should be done under name include_graph.ps"