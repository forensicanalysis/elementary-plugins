mkdir -p test/data

curl --fail --silent --output example1.forensicstore --location https://download.artifacthub.org/forensics/example1.forensicstore
mv example1.forensicstore test/data

curl --fail --silent --output example2.forensicstore --location https://download.artifacthub.org/forensics/example2.forensicstore
mv example2.forensicstore test/data

curl --fail --silent --output usb.forensicstore --location https://download.artifacthub.org/forensics/usb.forensicstore
mv usb.forensicstore test/data

curl --fail --silent --output win10_mock.zip --location https://download.artifacthub.org/windows/win10_mock.zip
unzip win10_mock.zip
mv win10_mock.vhd test/data
