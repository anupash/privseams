#!/bin/sh

echo "Generating configure files... may take a while."

autoreconf --install --force && \
  echo "Preparing was successful if there was no error messages above." && \
  echo "Now type:" && \
  echo "  ./configure && make"  && \
  echo "NOTE: The commands above only build the userspace apps." && \
  echo "NOTE: You have to build and install the linux kernel separately."
