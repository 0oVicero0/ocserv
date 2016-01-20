#!/bin/sh
serial=`date +%s%N`
echo "Please input your username for your certificate:"
read tmp1
echo "Please input your user's email for your certificate:"
read tmp2

#certtool --generate-privkey --outfile $tmp1.key.pem
openssl genrsa -out $tmp1.key.pem 4096
sed -i "1ccn = ${tmp1}" user.tmpl
sed -i "3cemail = ${tmp2}" user.tmpl
sed -i "6cserial = ${serial}" user.tmpl
certtool --generate-certificate --hash SHA256 --load-privkey $tmp1.key.pem --load-ca-certificate ../ca-cert.pem --load-ca-privkey ../ca-key.pem --template user.tmpl --outfile $tmp1.cert.pem
#for移动客户端P12证书
echo " "
echo "****** P12 certificate for Mobile Client, remember the name and password you enter, copy **mobile.${tmp1}.p12** to your mobile phone and install ******"
certtool --to-p12 --load-privkey $tmp1.key.pem --pkcs-cipher 3des-pkcs12 --load-certificate $tmp1.cert.pem --outfile mobile.$tmp1.p12 --outder
openssl pkcs12 -export -inkey $tmp1.key.pem -in $tmp1.cert.pem -certfile ../ca-cert.pem -out mobile.openssl.$tmp1.p12
#for Windows客户端P12证书
echo " "
echo "****** P12 certificate for Windows Client, remember the password you enter, copy **windows.${tmp1}.p12** to windows and install ******"
echo " "
openssl pkcs12 -export -inkey $tmp1.key.pem -in $tmp1.cert.pem -name "${tmp1}" -certfile ../ca-cert.pem -caname "Cisco CA" -out windows.$tmp1.p12
exit 0
