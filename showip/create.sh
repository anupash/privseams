#! /bin/sh

echo "Creating showip mozilla addon..."

rm showip-hipmod-0.8.02-fx-mz.xpi
rm inst/chrome/ipv6ident.jar

cd src
jar -cfM ../inst/chrome/ipv6ident.jar *
cd ../inst

zip -r ../showip-hipmod-0.8.02-fx-mz.xpi *

echo "Addon created."
