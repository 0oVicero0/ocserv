#!/bin/bash
####################################################
#                                                  #
# This is a ocserv installation for CentOS 7       #
# Version: 1.2.7 20150120                          #
# Author: Monokoo                                  #
# Thanks for original author: Travis Lee           #
####################################################
#  Version: 1.2.7 20150120
#  *更新ocserv的版本为0.10.11
#  *增加证书分组

#  Version: 1.2.6 20151229
#  *更新ocserv的版本为0.10.10

#  Version: 1.2.5 20151009
#  *源码下载改回作者的官方网站
#  *更新ocserv的版本为0.10.9

#  Version: 1.2.4 20150929
#  *源码下载改为从 github 下载，作者网站似乎挂了
#  *更新ocserv的版本为0.10.7
#  *更新libtasn1的版本为4.7

#  Version: 1.2.3 20150508
#  *更新libtasn1的版本为4.5
#  *更新ocserv的版本为0.10.4

#  Version: 1.2.2 20150402
#  *兼容CentOS 7.1，编译libtasn1-4.4替换系统的3.8版
#  *修正 修改src/vpn.h路由条数 的命令

#  +增加firewalld和iptables检测功能，使用systemctl is-active判断哪个防火墙在运行，请确保有一个防火墙自启动并加载默认配置
#  *把几个功能用function分隔，如果脚本运行遇到问题，可以注释已经完成的部分，修正后继续


#检测是否是root用户
if [[ $(id -u) != "0" ]]; then
    printf "\e[42m\e[31mError: You must be root to run this install script.\e[0m\n"
    exit 1
fi

#检测是否是CentOS 7或者RHEL 7
if [[ $(grep "release 7." /etc/redhat-release 2>/dev/null | wc -l) -eq 0 ]]; then
    printf "\e[42m\e[31mError: Your OS is NOT CentOS 7 or RHEL 7.\e[0m\n"
    printf "\e[42m\e[31mThis install script is ONLY for CentOS 7 and RHEL 7.\e[0m\n"
    exit 1
fi
#check install 防止重复安装
#    [ -f /usr/sbin/ocserv ]
#    printf "Not installed ok"

basepath=$(dirname $0)
cd ${basepath}

function ConfigEnvironmentVariable {
    #ocserv版本
    ocserv_version="0.10.11"
    version=${1-${ocserv_version}}
    libtasn1_version=4.7
    nettle_version=3.1
    gnutls_version=3.3.20
    #变量设置
    #单IP最大连接数，默认是2
    maxsameclients=2
    #最大连接数，默认是16
    maxclients=12
    #服务器的证书和key文件，放在本脚本的同目录下，key文件的权限应该是600或者400
    servercert=${2-server-cert.pem}
    serverkey=${3-server-key.pem}
    #配置目录，你可更改为 /etc/ocserv 之类的
    confdir="/opt/ocserv"

    #安装系统组件
    yum install -y -q net-tools bind-utils
    #获取网卡接口名称
    ethlist=$(ifconfig | grep ": flags" | cut -d ":" -f1)
    eth=$(printf "${ethlist}\n" | head -n 1)
    if [[ $(printf "${ethlist}\n" | wc -l) -gt 2 ]]; then
        echo ======================================
        echo "Network Interface list:"
        printf "\e[33m${ethlist}\e[0m\n"
        echo ======================================
        echo "Which network interface you want to listen for ocserv?"
        printf "Default network interface is \e[33m${eth}\e[0m, let it blank to use default network interface: "
        read ethtmp
        if [[ -n "${ethtmp}" ]]; then
            eth=${ethtmp}
        fi
    fi
    
    ipv4=$(ip -4 -f inet addr | grep "inet " | grep -v "lo:" | grep -v "127.0.0.1" | grep -o -P "\d+\.\d+\.\d+\.\d+\/\d+" | grep -o -P "\d+\.\d+\.\d+\.\d+")
   
    #端口，默认是10443
    port=10443
    echo "Please input the port ocserv listen to."
    printf "Default port is \e[33m${port}\e[0m, let it blank to use default port: "
    read porttmp
    if [[ -n "${porttmp}" ]]; then
        port=${porttmp}
    fi

    #设置证书CN名，默认是当前服务器IP地址
    cname=${ipv4}
    echo "Please input the cname for certificate. The default cname is your server's IP address"
    printf "Default cname is \e[33m${ipv4}\e[0m, let it blank to use default cname: "
    read cnametmp
    if [[ -n "${cnametmp}" ]]; then
        cname=${cnametmp}
    fi

    #用户名，默认是github
    username=github
    echo "Please input ocserv user name:"
    printf "Default user name is \e[33m${username}\e[0m, let it blank to use default user name: "
    read usernametmp
    if [[ -n "${usernametmp}" ]]; then
        username=${usernametmp}
    fi

    #随机密码
    randstr() {
        index=0
        str=""
        for i in {a..z}; do arr[index]=$i; index=$(expr ${index} + 1); done
        for i in {A..Z}; do arr[index]=$i; index=$(expr ${index} + 1); done
        for i in {0..9}; do arr[index]=$i; index=$(expr ${index} + 1); done
        for i in {1..10}; do str="$str${arr[$RANDOM%$index]}"; done
        echo ${str}
    }
    password=$(randstr)
    printf "Please input \e[33m${username}\e[0m's password:\n"
    printf "Default password is \e[33m${password}\e[0m, let it blank to use default password: "
    read passwordtmp
    if [[ -n "${passwordtmp}" ]]; then
        password=${passwordtmp}
    fi
}

function PrintEnvironmentVariable {
    #打印配置参数
    clear
    ipv4=$(ip -4 -f inet addr | grep "inet " | grep -v "lo:" | grep -v "127.0.0.1" | grep -o -P "\d+\.\d+\.\d+\.\d+\/\d+" | grep -o -P "\d+\.\d+\.\d+\.\d+")
    ipv6=$(ip -6 addr | grep "inet6" | grep -v "::1/128" | grep -o -P "([a-z\d]+:[a-z\d:]+\/\d+)" | grep -o -P "([a-z\d]+:[a-z\d:]+)")
    echo -e "IPv4:\t\t\e[34m$(echo ${ipv4})\e[0m"
    echo -e "IPv6:\t\t\e[34m$(echo ${ipv6})\e[0m"
    echo -e "Port:\t\t\e[34m${port}\e[0m"
    echo -e "Username:\t\e[34m${username}\e[0m"
    echo -e "Password:\t\e[34m${password}\e[0m"
    echo
    echo "Press any key to start install ocserv."

    get_char() {
        SAVEDSTTY=$(stty -g)
        stty -echo
        stty cbreak
        dd if=/dev/tty bs=1 count=1 2> /dev/null
        stty -raw
        stty echo
        stty ${SAVEDSTTY}
    }
    char=$(get_char)
    clear
}

function CompileOcserv {
    #升级系统
    #yum update -y -q
    #yum install -y -q epel-release
    #安装ocserv依赖组件
    yum install -y gnutls gnutls-utils gnutls-devel readline readline-devel texinfo
    yum install -y libnl-devel libtalloc libtalloc-devel libnl3-devel wget libidn unbound
    yum install -y pam pam-devel libtalloc-devel xz libseccomp-devel liboath* zlib bison bison-devel
    yum install -y tcp_wrappers trousers-devel gmp-devel libn1-devel libtasn1-devel flex
    yum install -y tcp_wrappers-devel autogen autogen-libopts-devel tar gcc pcre-devel openssl openssl-devel curl-devel 
    yum install -y freeradius-client-devel freeradius-client lz4-devel lz4 http-parser-devel http-parser 
    yum install -y protobuf-c-devel protobuf-c pcllib-devel pcllib cyrus-sasl-gssapi dbus-devel policycoreutils gperf

    #下载ocserv并编译
    wget -t 0 -T 60 "ftp://ftp.infradead.org/pub/ocserv/ocserv-${version}.tar.xz"
    #wget -t 0 -T 60 "https://github.com/mtmiller/ocserv/archive/ocserv_${version}.tar.gz" -O "ocserv-${version}.tar.gz"
    tar axf ocserv-${version}.tar.xz
    cd ocserv-${version}
    sed -i 's/#define DEFAULT_CONFIG_ENTRIES.*/#define DEFAULT_CONFIG_ENTRIES 200/g' src/vpn.h
    ./configure && make && make install

    #复制配置文件样本
    mkdir -p "${confdir}"
#   cp "doc/profile.xml" "${confdir}/profile.xml"
    cp "doc/sample.config" "${confdir}/ocserv.conf"
    cp "doc/systemd/standalone/ocserv.service" "/usr/lib/systemd/system/ocserv.service"
    cd ${basepath}
}

function UpdateComponents {
    cd ${basepath}   
    #import PKG_CONFIG_PATH 
    PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig:/usr/lib64/pkgconfig:/usr/local/lib/pkgconfig:/usr/lib/pkgconfig

    wget -t 0 -T 60 "http://ftp.gnu.org/gnu/libtasn1/libtasn1-${libtasn1_version}.tar.gz"
    tar axf libtasn1-${libtasn1_version}.tar.gz
    cd libtasn1-${libtasn1_version}
    ./configure --prefix=/usr --libdir=/usr/lib64 --includedir=/usr/include
    make && make install
    cd ..

    #增加libgnutls环境变量
    ##export LIBGNUTLS_CFLAGS="-I/usr/include/" LIBGNUTLS_LIBS="-L/usr/lib/ -lgnutls"

    #编译nettle
    wget -t 0 -T 60 "https://ftp.gnu.org/gnu/nettle/nettle-${nettle_version}.tar.gz" && tar -axf nettle-${nettle_version}.tar.gz && cd nettle-${nettle_version}
    ./configure --prefix=/usr --enable-shared 
     make && make install

    #编译gnutls
    cd ..
    wget -t 0 -T 60 "ftp://ftp.gnutls.org/gcrypt/gnutls/v3.3/gnutls-${gnutls_version}.tar.xz" && tar -xaf gnutls-${gnutls_version}.tar.xz && cd gnutls-${gnutls_version}
    ./configure --prefix=/usr --enable-shared
     make && make install
     cd ${basepath}
}

function ConfigOcserv {
    ipv4=$(ip -4 -f inet addr | grep "inet " | grep -v "lo:" | grep -v "127.0.0.1" | grep -o -P "\d+\.\d+\.\d+\.\d+\/\d+" | grep -o -P "\d+\.\d+\.\d+\.\d+")
    #检测是否有证书和key文件
    if [[ ! -f "${servercert}" ]] || [[ ! -f "${serverkey}" ]]; then
        #创建ca证书和服务器证书（参考http://www.infradead.org/ocserv/manual.html#heading5）
     openssl genrsa -out ca-key.pem 4096
cat << _EOF_ >ca.tmpl
cn = "Cisco CA"
state = "Shanghai"
country = CN
organization = "Cisco"
serial = 1
expiration_days = 1825
email = "youremail@gmail.com"
dns_name = ${cname}
ca
signing_key
encryption_key
cert_signing_key
crl_signing_key
_EOF_

      certtool --generate-self-signed --hash SHA256 --load-privkey ca-key.pem --template ca.tmpl --outfile ca-cert.pem
#     openssl req -new -newkey rsa:4096 -sha256 -nodes -out server.csr -keyout server-key.pem
      openssl genrsa -out ${serverkey} 4096
cat << _EOF_ >server.tmpl
cn = ${cname}
o = "Cisco"
email = "youremail@gmail.com"
dns_name = ${cname}
country = CN
state = "Shanghai"
serial = 2
expiration_days = 1825
signing_key
encryption_key #only if the generated key is an RSA one
tls_www_server
_EOF_

     certtool --generate-certificate --hash SHA256 --load-privkey ${serverkey} --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem --template server.tmpl --outfile server-self-signed-cert.pem
     certtool --generate-request --hash SHA256  --load-privkey ${serverkey} --template server.tmpl --outfile server-cert.csr	 
#    openssl genrsa -out user-key.pem 2048
		
cat << _EOF_ >user.tmpl
cn = "AnyClient"
unit = "Route"
email = "youremail@gmail.com"
dns_name = ${cname}
country = CN
serial = 3
expiration_days = 365
signing_key
tls_www_client
_EOF_

#     certtool --generate-certificate --hash SHA256 --load-privkey user-key.pem --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem --template user.tmpl --outfile user-cert.pem

	 #for移动客户端P12证书
#	 echo "****** P12 certificate for Mobile Client, remember the name and password you enter, copy **mobile.user.p12** to your mobile phone and install ******"
 #    certtool --to-p12 --load-privkey user-key.pem --pkcs-cipher 3des-pkcs12 --load-certificate user-cert.pem --outfile mobile.user.p12 --outder

	 #for Windows客户端P12证书
#	 echo "****** P12 certificate for Windows Client, remember the password you enter, copy **windows.user.p12** to windows and install ******"
#     openssl pkcs12 -export -inkey user-key.pem -in user-cert.pem -name "winClient" -certfile ca-cert.pem -caname "Cisco CA" -out windows.user.p12
    fi

    #把证书复制到ocserv的配置目录
    cp server-cert.csr "${confdir}" && cp "${serverkey}" "${confdir}" && cp "ca-cert.pem" "${confdir}" && cp "ca-key.pem" "${confdir}" && cp server-self-signed-cert.pem "${confdir}"
    cp server-self-signed-cert.pem $confdir/server.cert.pem

    #copy the shell script to make the user's cert
    mkdir -p $confdir/usercert
    wget --no-check-certificate https://raw.githubusercontent.com/monokoo/Ocserv-install-script-for-CentOS-RHEL-7/master/make-client.sh  && chmod +x make-client.sh
	cp make-client.sh $confdir/usercert/ && cp user.tmpl $confdir/usercert/ 

    #编辑配置文件
    (echo "${password}"; sleep 1; echo "${password}") | ocpasswd -g "All,Route,NoRoute" -c "${confdir}/ocpasswd" ${username}

    sed -i "s#./sample.passwd#${confdir}/ocpasswd#g" "${confdir}/ocserv.conf"
    sed -i 's/#enable-auth = "certificate"/enable-auth = "certificate"/g' "${confdir}/ocserv.conf"
    sed -i 's/try-mtu-discovery = false/try-mtu-discovery = true/g' "${confdir}/ocserv.conf"
    sed -i 's/cert-user-oid = 0.9.2342.19200300.100.1.1/cert-user-oid = 2.5.4.3/g' "${confdir}/ocserv.conf"
    sed -i 's/#cert-group-oid = 2.5.4.11/cert-group-oid = 2.5.4.11/g' "${confdir}/ocserv.conf"
    sed -i "s#server-cert = ../tests/server-cert.pem#server-cert = ${confdir}/server-cert.pem#g" "${confdir}/ocserv.conf"
    sed -i "s#server-key = ../tests/server-key.pem#server-key = ${confdir}/${serverkey}#g" "${confdir}/ocserv.conf"
    sed -i "s#ca-cert = ../tests/ca.pem#ca-cert = ${confdir}/ca-cert.pem#g" "${confdir}/ocserv.conf"
    sed -i "s/max-same-clients = 2/max-same-clients = ${maxsameclients}/g" "${confdir}/ocserv.conf"
    sed -i "s/max-clients = 16/max-clients = ${maxclients}/g" "${confdir}/ocserv.conf"
    sed -i 's/#compression = true/compression = true/g' "${confdir}/ocserv.conf"
    sed -i 's/#no-compress-limit = 256/no-compress-limit = 256/g' "${confdir}/ocserv.conf"
    sed -i 's/#ban-points-wrong-password = 10/ban-points-wrong-password = 10/g' "${confdir}/ocserv.conf"
    sed -i "s/tcp-port = 443/tcp-port = ${port}/g" "${confdir}/ocserv.conf"
    sed -i "s/udp-port = 443/udp-port = ${port}/g" "${confdir}/ocserv.conf"
    sed -i "s/#output-buffer = 10/output-buffer = 10000/g" "${confdir}/ocserv.conf"
    sed -i "s/mobile-dpd = 1800/mobile-dpd = 600/g" "${confdir}/ocserv.conf"
    sed -i "s/ipv4-network = 192.168.1.0/ipv4-network = 192.168.8.0/g" "${confdir}/ocserv.conf"
    sed -i "s/dns = 192.168.1.2/dns = 208.67.220.220\ndns = 8.8.8.8/g" "${confdir}/ocserv.conf"
    sed -i "s/isolate-workers = true/isolate-workers = false/g" "${confdir}/ocserv.conf"
    sed -i "s/cookie-timeout = 300/cookie-timeout = 86400/g" "${confdir}/ocserv.conf"
    sed -i 's/isolate-workers = true/isolate-workers = false/g' "${confdir}/ocserv.conf"
    sed -i "s#default-domain = example.com#default-domain = ${cname}#g" "${confdir}/ocserv.conf"
    sed -i 's$route = 10.10.10.0/255.255.255.0$#route = 10.10.10.0/255.255.255.0$g' "${confdir}/ocserv.conf"
    sed -i 's$route = 192.168.0.0/255.255.0.0$#route = 192.168.0.0/255.255.0.0$g' "${confdir}/ocserv.conf"
    sed -i 's$no-route = 192.168.5.0/255.255.255.0$#no-route = 192.168.5.0/255.255.255.0$' "${confdir}/ocserv.conf"
    sed -i 's/#select-group = group1/select-group = All/g' "${confdir}/ocserv.conf"
    sed -i 's/#select-group = group2\[My special group\]/select-group = Route/g' "${confdir}/ocserv.conf"
    sed -i '/select-group = Route/a\select-group = NoRoute' "${confdir}/ocserv.conf"
    sed -i 's/#default-select-group = DEFAULT/default-select-group = All/g' "${confdir}/ocserv.conf"
    sed -i 's/#auto-select-group = true/auto-select-group = false/g' "${confdir}/ocserv.conf"
    sed -i 's$#config-per-group = /etc/ocserv/config-per-group\/$config-per-group = /opt/ocserv/config-per-group$g' "${confdir}/ocserv.conf"
    sed -i 's$#default-group-config = /etc/ocserv/defaults/group.conf$default-group-config = /opt/ocserv/config-per-group/group.conf$' "${confdir}/ocserv.conf"
	
    mkdir -p ${confdir}/config-per-group
    
	cat << _EOF_ >>${confdir}/config-per-group/All
route = 0.0.0.0/128.0.0.0
route = 128.0.0.0/128.0.0.0
_EOF_
    
   cp $confdir/config-per-group/All $confdir/config-per-group/group.conf

    cat << _EOF_ >>${confdir}/config-per-group/NoRoute
no-route = 1.0.0.0/255.192.0.0
no-route = 1.64.0.0/255.224.0.0
no-route = 1.112.0.0/255.248.0.0
no-route = 1.176.0.0/255.240.0.0
no-route = 1.192.0.0/255.240.0.0
no-route = 14.0.0.0/255.224.0.0
no-route = 14.96.0.0/255.224.0.0
no-route = 14.128.0.0/255.224.0.0
no-route = 14.192.0.0/255.224.0.0
no-route = 27.0.0.0/255.192.0.0
no-route = 27.96.0.0/255.224.0.0
no-route = 27.128.0.0/255.224.0.0
no-route = 27.176.0.0/255.240.0.0
no-route = 27.192.0.0/255.224.0.0
no-route = 27.224.0.0/255.252.0.0
no-route = 36.0.0.0/255.192.0.0
no-route = 36.96.0.0/255.224.0.0
no-route = 36.128.0.0/255.192.0.0
no-route = 36.192.0.0/255.224.0.0
no-route = 36.240.0.0/255.240.0.0
no-route = 39.0.0.0/255.255.0.0
no-route = 39.64.0.0/255.224.0.0
no-route = 39.96.0.0/255.240.0.0
no-route = 39.128.0.0/255.192.0.0
no-route = 40.72.0.0/255.254.0.0
no-route = 40.125.128.0/255.255.128.0
no-route = 40.126.64.0/255.255.192.0
no-route = 42.0.0.0/255.248.0.0
no-route = 42.48.0.0/255.240.0.0
no-route = 42.80.0.0/255.240.0.0
no-route = 42.96.0.0/255.224.0.0
no-route = 42.128.0.0/255.128.0.0
no-route = 43.224.0.0/255.224.0.0
no-route = 45.112.0.0/255.240.0.0
no-route = 47.92.0.0/255.252.0.0
no-route = 47.96.0.0/255.224.0.0
no-route = 49.0.0.0/255.248.0.0
no-route = 49.48.0.0/255.248.0.0
no-route = 49.64.0.0/255.224.0.0
no-route = 49.112.0.0/255.240.0.0
no-route = 49.128.0.0/255.224.0.0
no-route = 49.208.0.0/255.240.0.0
no-route = 49.224.0.0/255.224.0.0
no-route = 52.80.0.0/255.252.0.0
no-route = 54.222.0.0/255.254.0.0
no-route = 58.0.0.0/255.128.0.0
no-route = 58.128.0.0/255.224.0.0
no-route = 58.192.0.0/255.224.0.0
no-route = 58.240.0.0/255.240.0.0
no-route = 59.32.0.0/255.224.0.0
no-route = 59.64.0.0/255.224.0.0
no-route = 59.96.0.0/255.240.0.0
no-route = 59.144.0.0/255.240.0.0
no-route = 59.160.0.0/255.224.0.0
no-route = 59.192.0.0/255.192.0.0
no-route = 60.0.0.0/255.224.0.0
no-route = 60.48.0.0/255.240.0.0
no-route = 60.160.0.0/255.224.0.0
no-route = 60.192.0.0/255.192.0.0
no-route = 61.0.0.0/255.192.0.0
no-route = 61.80.0.0/255.248.0.0
no-route = 61.128.0.0/255.192.0.0
no-route = 61.224.0.0/255.224.0.0
no-route = 91.234.36.0/255.255.255.0
no-route = 101.0.0.0/255.128.0.0
no-route = 101.128.0.0/255.224.0.0
no-route = 101.192.0.0/255.240.0.0
no-route = 101.224.0.0/255.224.0.0
no-route = 103.0.0.0/255.192.0.0
no-route = 103.192.0.0/255.240.0.0
no-route = 103.224.0.0/255.224.0.0
no-route = 106.0.0.0/255.128.0.0
no-route = 106.224.0.0/255.240.0.0
no-route = 110.0.0.0/255.128.0.0
no-route = 110.144.0.0/255.240.0.0
no-route = 110.160.0.0/255.224.0.0
no-route = 110.192.0.0/255.192.0.0
no-route = 111.0.0.0/255.192.0.0
no-route = 111.64.0.0/255.224.0.0
no-route = 111.112.0.0/255.240.0.0
no-route = 111.128.0.0/255.192.0.0
no-route = 111.192.0.0/255.224.0.0
no-route = 111.224.0.0/255.240.0.0
no-route = 112.0.0.0/255.128.0.0
no-route = 112.128.0.0/255.240.0.0
no-route = 112.192.0.0/255.252.0.0
no-route = 112.224.0.0/255.224.0.0
no-route = 113.0.0.0/255.128.0.0
no-route = 113.128.0.0/255.240.0.0
no-route = 113.192.0.0/255.192.0.0
no-route = 114.16.0.0/255.240.0.0
no-route = 114.48.0.0/255.240.0.0
no-route = 114.64.0.0/255.192.0.0
no-route = 114.128.0.0/255.240.0.0
no-route = 114.192.0.0/255.192.0.0
no-route = 115.0.0.0/255.0.0.0
no-route = 116.0.0.0/255.0.0.0
no-route = 117.0.0.0/255.128.0.0
no-route = 117.128.0.0/255.192.0.0
no-route = 118.16.0.0/255.240.0.0
no-route = 118.64.0.0/255.192.0.0
no-route = 118.128.0.0/255.128.0.0
no-route = 119.0.0.0/255.128.0.0
no-route = 119.128.0.0/255.192.0.0
no-route = 119.224.0.0/255.224.0.0
no-route = 120.0.0.0/255.192.0.0
no-route = 120.64.0.0/255.224.0.0
no-route = 120.128.0.0/255.240.0.0
no-route = 120.192.0.0/255.192.0.0
no-route = 121.0.0.0/255.128.0.0
no-route = 121.192.0.0/255.192.0.0
no-route = 122.0.0.0/254.0.0.0
no-route = 124.0.0.0/255.0.0.0
no-route = 125.0.0.0/255.128.0.0
no-route = 125.160.0.0/255.224.0.0
no-route = 125.192.0.0/255.192.0.0
no-route = 137.59.88.0/255.255.252.0
no-route = 139.0.0.0/255.224.0.0
no-route = 139.128.0.0/255.128.0.0
no-route = 140.64.0.0/255.240.0.0
no-route = 140.128.0.0/255.240.0.0
no-route = 140.192.0.0/255.192.0.0
no-route = 144.0.0.0/255.255.0.0
no-route = 144.7.0.0/255.255.0.0
no-route = 144.12.0.0/255.255.0.0
no-route = 144.52.0.0/255.255.0.0
no-route = 144.123.0.0/255.255.0.0
no-route = 144.255.0.0/255.255.0.0
no-route = 150.0.0.0/255.255.0.0
no-route = 150.96.0.0/255.224.0.0
no-route = 150.128.0.0/255.240.0.0
no-route = 150.192.0.0/255.192.0.0
no-route = 152.104.128.0/255.255.128.0
no-route = 153.0.0.0/255.192.0.0
no-route = 153.96.0.0/255.224.0.0
no-route = 157.0.0.0/255.255.0.0
no-route = 157.18.0.0/255.255.0.0
no-route = 157.61.0.0/255.255.0.0
no-route = 157.122.0.0/255.255.0.0
no-route = 157.148.0.0/255.255.0.0
no-route = 157.156.0.0/255.255.0.0
no-route = 157.255.0.0/255.255.0.0
no-route = 159.226.0.0/255.255.0.0
no-route = 161.207.0.0/255.255.0.0
no-route = 162.105.0.0/255.255.0.0
no-route = 163.0.0.0/255.192.0.0
no-route = 163.96.0.0/255.224.0.0
no-route = 163.128.0.0/255.192.0.0
no-route = 163.192.0.0/255.224.0.0
no-route = 166.111.0.0/255.255.0.0
no-route = 167.139.0.0/255.255.0.0
no-route = 167.189.0.0/255.255.0.0
no-route = 167.220.244.0/255.255.252.0
no-route = 168.160.0.0/255.255.0.0
no-route = 171.0.0.0/255.128.0.0
no-route = 171.192.0.0/255.224.0.0
no-route = 175.0.0.0/255.128.0.0
no-route = 175.128.0.0/255.192.0.0
no-route = 180.64.0.0/255.192.0.0
no-route = 180.128.0.0/255.128.0.0
no-route = 182.0.0.0/255.0.0.0
no-route = 183.0.0.0/255.192.0.0
no-route = 183.64.0.0/255.224.0.0
no-route = 183.128.0.0/255.128.0.0
no-route = 192.124.154.0/255.255.255.0
no-route = 192.188.170.0/255.255.255.0
no-route = 202.0.0.0/255.128.0.0
no-route = 202.128.0.0/255.192.0.0
no-route = 202.192.0.0/255.224.0.0
no-route = 203.0.0.0/255.128.0.0
no-route = 203.128.0.0/255.192.0.0
no-route = 203.192.0.0/255.224.0.0
no-route = 210.0.0.0/255.192.0.0
no-route = 210.64.0.0/255.224.0.0
no-route = 210.160.0.0/255.224.0.0
no-route = 210.192.0.0/255.224.0.0
no-route = 211.64.0.0/255.248.0.0
no-route = 211.80.0.0/255.240.0.0
no-route = 211.96.0.0/255.248.0.0
no-route = 211.136.0.0/255.248.0.0
no-route = 211.144.0.0/255.240.0.0
no-route = 211.160.0.0/255.248.0.0
no-route = 218.0.0.0/255.128.0.0
no-route = 218.160.0.0/255.224.0.0
no-route = 218.192.0.0/255.192.0.0
no-route = 219.64.0.0/255.224.0.0
no-route = 219.128.0.0/255.224.0.0
no-route = 219.192.0.0/255.192.0.0
no-route = 220.96.0.0/255.224.0.0
no-route = 220.128.0.0/255.128.0.0
no-route = 221.0.0.0/255.224.0.0
no-route = 221.96.0.0/255.224.0.0
no-route = 221.128.0.0/255.128.0.0
no-route = 222.0.0.0/255.0.0.0
no-route = 223.0.0.0/255.224.0.0
no-route = 223.64.0.0/255.192.0.0
no-route = 223.128.0.0/255.128.0.0
_EOF_

    cat << _EOF_ >>${confdir}/config-per-group/Route
route = 8.0.0.0/252.0.0.0
route = 16.0.0.0/248.0.0.0
route = 23.0.0.0/255.0.0.0
route = 31.13.64.0/255.255.192.0
route = 50.0.0.0/255.0.0.0
route = 54.0.0.0/255.128.0.0
route = 54.128.0.0/255.192.0.0
route = 66.220.144.0/255.255.240.0
route = 69.0.0.0/255.0.0.0
route = 72.0.0.0/255.0.0.0
route = 73.0.0.0/255.0.0.0
route = 74.0.0.0/255.0.0.0
route = 78.0.0.0/255.0.0.0
route = 92.0.0.0/255.0.0.0
route = 93.0.0.0/255.0.0.0
route = 96.0.0.0/255.0.0.0
route = 97.0.0.0/255.0.0.0
route = 104.0.0.0/248.0.0.0
route = 109.0.0.0/255.0.0.0
route = 128.0.0.0/255.0.0.0
route = 141.0.0.0/255.0.0.0
route = 173.0.0.0/255.0.0.0
route = 174.0.0.0/255.0.0.0
route = 176.0.0.0/255.0.0.0
route = 190.0.0.0/255.0.0.0
route = 192.0.0.0/255.0.0.0
route = 198.0.0.0/255.0.0.0
route = 199.0.0.0/255.0.0.0
route = 205.0.0.0/255.0.0.0
route = 206.0.0.0/255.0.0.0
route = 208.0.0.0/255.0.0.0
route = 210.128.0.0/255.192.0.0
route = 216.0.0.0/255.0.0.0
route = 220.128.0.0/255.128.0.0
_EOF_

    #修改ocserv服务
    sed -i "s#/usr/sbin/ocserv#/usr/local/sbin/ocserv#g" "/usr/lib/systemd/system/ocserv.service"
    sed -i "s#/etc/ocserv/ocserv.conf#$confdir/ocserv.conf#g" "/usr/lib/systemd/system/ocserv.service"
}

function ConfigFirewall {

iptablesisactive=$(systemctl is-active iptables.service)

if [[ ${iptablesisactive} = 'active' ]]; then
    #添加防火墙允许列表
    echo "Adding firewall ports."
    sed -i '/INPUT -j REJECT --reject-with icmp-host-prohibited/i\-A INPUT -p tcp -m tcp --dport '$port' -j ACCEPT' /etc/sysconfig/iptables
    sed -i '/INPUT -j REJECT --reject-with icmp-host-prohibited/i\-A INPUT -p udp -m udp --dport '$port' -j ACCEPT' /etc/sysconfig/iptables
    sed -i '/FORWARD -j REJECT --reject-with icmp-host-prohibited/i\-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT' /etc/sysconfig/iptables
    sed -i '/FORWARD -j REJECT --reject-with icmp-host-prohibited/i\-A FORWARD -s 192.168.8.0/21 -j ACCEPT' /etc/sysconfig/iptables
    sed -i '/FORWARD -j REJECT --reject-with icmp-host-prohibited/i\-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu' /etc/sysconfig/iptables
    service iptables restart
    iptables -t nat -A POSTROUTING -j MASQUERADE
#	iptables -P INPUT DROP
#   iptables -t mangle -A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    service iptables save
else
    printf "\e[33mWARNING!!! Either firewalld or iptables is NOT Running! \e[0m\n"
    yum install iptables-services -y
	service iptables restart
	systemctl enable iptables 
    sed -i '/INPUT -j REJECT --reject-with icmp-host-prohibited/i\-A INPUT -p tcp --dport '$port' -j ACCEPT' /etc/sysconfig/iptables
    sed -i '/INPUT -j REJECT --reject-with icmp-host-prohibited/i\-A INPUT -p udp --dport '$port' -j ACCEPT' /etc/sysconfig/iptables
    sed -i '/FORWARD -j REJECT --reject-with icmp-host-prohibited/i\-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT' /etc/sysconfig/iptables
    sed -i '/FORWARD -j REJECT --reject-with icmp-host-prohibited/i\-A FORWARD -s 192.168.8.0/21 -j ACCEPT' /etc/sysconfig/iptables
    sed -i '/FORWARD -j REJECT --reject-with icmp-host-prohibited/i\-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu' /etc/sysconfig/iptables
    service iptables restart
    iptables -t nat -A POSTROUTING -j MASQUERADE
#	iptables -P INPUT DROP
#   iptables -t mangle -A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    service iptables save
fi
}

function ConfigSystem {
    #关闭selinux
    sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
    setenforce 0
    #修改系统
    echo "Enable IP forward."
    sysctl -w net.ipv4.ip_forward=1
    echo net.ipv4.ip_forward = 1 >> "/etc/sysctl.conf"
    systemctl daemon-reload
    echo "Enable ocserv service to start during bootup."
    systemctl enable ocserv.service
    #开启ocserv服务
    systemctl start ocserv.service
    echo
    source /etc/profile
}

function PrintResult {
    #检测防火墙和ocserv服务是否正常
    clear
    printf "\e[36mChenking Firewall status...\e[0m\n"
    iptables -L -n | grep --color=auto -E "(${port}|192.168.8.0)"
    line=$(iptables -L -n | grep -c -E "(${port}|192.168.8.0)")
    if [[ ${line} -ge 2 ]]
    then
        printf "\e[34mFirewall is Fine! \e[0m\n"
    else
        printf "\e[33mWARNING!!! Firewall is Something Wrong! \e[0m\n"
    fi

    echo
    printf "\e[36mChenking ocserv service status...\e[0m\n"
    netstat -anp | grep ":${port}" | grep --color=auto -E "(${port}|ocserv|tcp|udp)"
    linetcp=$(netstat -anp | grep ":${port}" | grep ocserv | grep tcp | wc -l)
    lineudp=$(netstat -anp | grep ":${port}" | grep ocserv | grep udp | wc -l)
    if [[ ${linetcp} -ge 1 && ${lineudp} -ge 1 ]]
    then
        printf "\e[34mocserv service is Fine! \e[0m\n"
    else
        printf "\e[33mWARNING!!! ocserv service is NOT Running! \e[0m\n"
    fi
    #rm -rf nettle*
    #rm -rf gnutls*
    #rm -rf libtasn1*
    #打印VPN参数
    printf "
    if there are \e[33mNO WARNING\e[0m above, then you can connect to
    your ocserv VPN Server with the default user/password below:
    ======================================\n"
    echo -e "IPv4:\t\t\e[34m$(echo ${ipv4})\e[0m"
    echo -e "IPv6:\t\t\e[34m$(echo ${ipv6})\e[0m"
    echo -e "Port:\t\t\e[34m${port}\e[0m"
    echo -e "Username:\t\e[34m${username}\e[0m"
    echo -e "Password:\t\e[34m${password}\e[0m"
}

ConfigEnvironmentVariable
PrintEnvironmentVariable
CompileOcserv $@
ConfigOcserv
#UpdateComponents
ConfigFirewall
ConfigSystem
PrintResult
exit 0
