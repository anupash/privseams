#!/bin/sh

echo "Generating configure files... may take a while."

echo "Configuring pjproject"
cd pjproject && ./configure $@ || (echo "Failed to configure pjproject" && exit 1)
make dep
cd ..

echo "Pjproject was configured successfully"
echo "Now configuring hipl with default configure optons"
autoreconf --install --force && ./configure $@ && make  && \
  echo "" && \
  echo "NOTE: The commands above only build the userspace apps." && \
  echo "NOTE: You have to build and install the linux kernel separately." && \
  echo "NOTE: You cannot use HIP without applying the interfamily and beet from the patches directory to your kernel!"
  echo "NOTE: Some features (e.g. firewall ) require './configure --enable-FEATURE'"
  echo "NOTE: Run './configure --help' for more information"
  echo "NOTE: libjip and hipsock need to be compiled separately with make"
