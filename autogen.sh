 #!/bin/sh

echo "Generating configure files... may take a while."

autoreconf --install --force && \
  echo "Preparing was successful if there was no error messages above." && \
  echo "Now type:" && \
  echo "  ./configure && make"  && \
  echo "NOTE: The commands above only build the userspace apps." && \
  echo "NOTE: You have to build and install the linux kernel separately." && \
  echo "NOTE: You cannot use HIP without applying the interfamily and beet from the patches directory to your kernel!"
  echo "NOTE: Some features (e.g. firewall ) require './configure --enable-FEATURE'"
  echo "NOTE: Run './configure --help' for more information"
  echo "NOTE: libjip and hipsock need to be compiled separately with make"
