#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
#	System Required: CentOS 6+/Debian 6+/Ubuntu 14.04+
#	Description: Install the ShadowsocksR mudbjson server
#	Version: 1.0.26
#	Author: Toyo
#	Blog: https://doub.io/ss-jc60/
#=================================================

sh_ver="1.0.26"
filepath=$(cd "$(dirname "$0")"; pwd)
file=$(echo -e "${filepath}"|awk -F "$0" '{print $1}')
ssr_folder="/usr/local/shadowsocksr"
config_file="${ssr_folder}/config.json"
config_user_file="${ssr_folder}/user-config.json"
config_user_api_file="${ssr_folder}/userapiconfig.py"
config_user_mudb_file="${ssr_folder}/mudb.json"
ssr_log_file="${ssr_folder}/ssserver.log"
Libsodiumr_file="/usr/local/lib/libsodium.so"
Libsodiumr_ver_backup="1.0.15"
Server_Speeder_file="/serverspeeder/bin/serverSpeeder.sh"
LotServer_file="/appex/bin/serverSpeeder.sh"
BBR_file="${file}/bbr.sh"
jq_file="${ssr_folder}/jq"

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[information]${Font_color_suffix}"
Error="${Red_font_prefix}[error]${Font_color_suffix}"
Tip="${Green_font_prefix}[note]${Font_color_suffix}"
Separator_1="——————————————————————————————"

check_root(){
	[[ $EUID != 0 ]] && echo -e "${Error} Current account is not ROOT(Or not ROOT Authority)，Unable to continue，please use${Green_background_prefix} sudo su ${Font_color_suffix}To get temporary ROOT Authority（After execution, you will be prompted to enter the password of the current account）。" && exit 1
}
check_sys(){
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
    fi
	bit=`uname -m`
}
check_pid(){
	PID=`ps -ef |grep -v grep | grep server.py |awk '{print $2}'`
}
check_crontab(){
	[[ ! -e "/usr/bin/crontab" ]] && echo -e "${Error} Lack of dependency Crontab ，Please try to install manually CentOS: yum install crond -y , Debian/Ubuntu: apt-get install cron -y !" && exit 1
}
SSR_installation_status(){
	[[ ! -e ${ssr_folder} ]] && echo -e "${Error} not found ShadowsocksR Folder, please check !" && exit 1
}
Server_Speeder_installation_status(){
	[[ ! -e ${Server_Speeder_file} ]] && echo -e "${Error} Not installed sharp speed(Server Speeder)，Please check !" && exit 1
}
LotServer_installation_status(){
	[[ ! -e ${LotServer_file} ]] && echo -e "${Error} Not installed LotServer，Please check !" && exit 1
}
BBR_installation_status(){
	if [[ ! -e ${BBR_file} ]]; then
		echo -e "${Error} not found BBR script，start download..."
		cd "${file}"
		if ! wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/bbr.sh; then
			echo -e "${Error} BBR Script download failed !" && exit 1
		else
			echo -e "${Info} BBR Script download completed !"
			chmod +x bbr.sh
		fi
	fi
}
# Set up firewall rules
Add_iptables(){
	if [[ ! -z "${ssr_port}" ]]; then
		iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssr_port} -j ACCEPT
		iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssr_port} -j ACCEPT
		ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssr_port} -j ACCEPT
		ip6tables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssr_port} -j ACCEPT
	fi
}
Del_iptables(){
	if [[ ! -z "${port}" ]]; then
		iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
		iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
		ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
		ip6tables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
	fi
}
Save_iptables(){
	if [[ ${release} == "centos" ]]; then
		service iptables save
		service ip6tables save
	else
		iptables-save > /etc/iptables.up.rules
		ip6tables-save > /etc/ip6tables.up.rules
	fi
}
Set_iptables(){
	if [[ ${release} == "centos" ]]; then
		service iptables save
		service ip6tables save
		chkconfig --level 2345 iptables on
		chkconfig --level 2345 ip6tables on
	else
		iptables-save > /etc/iptables.up.rules
		ip6tables-save > /etc/ip6tables.up.rules
		echo -e '#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules\n/sbin/ip6tables-restore < /etc/ip6tables.up.rules' > /etc/network/if-pre-up.d/iptables
		chmod +x /etc/network/if-pre-up.d/iptables
	fi
}
# Read configuration information
Get_IP(){
	ip=$(wget -qO- -t1 -T2 ipinfo.io/ip)
	if [[ -z "${ip}" ]]; then
		ip=$(wget -qO- -t1 -T2 api.ip.sb/ip)
		if [[ -z "${ip}" ]]; then
			ip=$(wget -qO- -t1 -T2 members.3322.org/dyndns/getip)
			if [[ -z "${ip}" ]]; then
				ip="VPS_IP"
			fi
		fi
	fi
}
Get_User_info(){
	Get_user_port=$1
	user_info_get=$(python mujson_mgr.py -l -p "${Get_user_port}")
	match_info=$(echo "${user_info_get}"|grep -w "### user ")
	if [[ -z "${match_info}" ]]; then
		echo -e "${Error} Failed to obtain user information ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} " && exit 1
	fi
	user_name=$(echo "${user_info_get}"|grep -w "user :"|awk -F "user : " '{print $NF}')
	port=$(echo "${user_info_get}"|grep -w "port :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	password=$(echo "${user_info_get}"|grep -w "passwd :"|awk -F "passwd : " '{print $NF}')
	method=$(echo "${user_info_get}"|grep -w "method :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	protocol=$(echo "${user_info_get}"|grep -w "protocol :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	protocol_param=$(echo "${user_info_get}"|grep -w "protocol_param :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	[[ -z ${protocol_param} ]] && protocol_param="0(unlimited)"
	obfs=$(echo "${user_info_get}"|grep -w "obfs :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	#transfer_enable=$(echo "${user_info_get}"|grep -w "transfer_enable :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}'|awk -F "ytes" '{print $1}'|sed 's/KB/ KB/;s/MB/ MB/;s/GB/ GB/;s/TB/ TB/;s/PB/ PB/')
	#u=$(echo "${user_info_get}"|grep -w "u :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	#d=$(echo "${user_info_get}"|grep -w "d :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	forbidden_port=$(echo "${user_info_get}"|grep -w "forbidden_port :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	[[ -z ${forbidden_port} ]] && forbidden_port="unlimited"
	speed_limit_per_con=$(echo "${user_info_get}"|grep -w "speed_limit_per_con :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	speed_limit_per_user=$(echo "${user_info_get}"|grep -w "speed_limit_per_user :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	Get_User_transfer "${port}"
}
Get_User_transfer(){
	transfer_port=$1
	#echo "transfer_port=${transfer_port}"
	all_port=$(${jq_file} '.[]|.port' ${config_user_mudb_file})
	#echo "all_port=${all_port}"
	port_num=$(echo "${all_port}"|grep -nw "${transfer_port}"|awk -F ":" '{print $1}')
	#echo "port_num=${port_num}"
	port_num_1=$(echo $((${port_num}-1)))
	#echo "port_num_1=${port_num_1}"
	transfer_enable_1=$(${jq_file} ".[${port_num_1}].transfer_enable" ${config_user_mudb_file})
	#echo "transfer_enable_1=${transfer_enable_1}"
	u_1=$(${jq_file} ".[${port_num_1}].u" ${config_user_mudb_file})
	#echo "u_1=${u_1}"
	d_1=$(${jq_file} ".[${port_num_1}].d" ${config_user_mudb_file})
	#echo "d_1=${d_1}"
	transfer_enable_Used_2_1=$(echo $((${u_1}+${d_1})))
	#echo "transfer_enable_Used_2_1=${transfer_enable_Used_2_1}"
	transfer_enable_Used_1=$(echo $((${transfer_enable_1}-${transfer_enable_Used_2_1})))
	#echo "transfer_enable_Used_1=${transfer_enable_Used_1}"
	
	if [[ ${transfer_enable_1} -lt 1024 ]]; then
		transfer_enable="${transfer_enable_1} B"
	elif [[ ${transfer_enable_1} -lt 1048576 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1024'}')
		transfer_enable="${transfer_enable} KB"
	elif [[ ${transfer_enable_1} -lt 1073741824 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1048576'}')
		transfer_enable="${transfer_enable} MB"
	elif [[ ${transfer_enable_1} -lt 1099511627776 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1073741824'}')
		transfer_enable="${transfer_enable} GB"
	elif [[ ${transfer_enable_1} -lt 1125899906842624 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1099511627776'}')
		transfer_enable="${transfer_enable} TB"
	fi
	#echo "transfer_enable=${transfer_enable}"
	if [[ ${u_1} -lt 1024 ]]; then
		u="${u_1} B"
	elif [[ ${u_1} -lt 1048576 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1024'}')
		u="${u} KB"
	elif [[ ${u_1} -lt 1073741824 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1048576'}')
		u="${u} MB"
	elif [[ ${u_1} -lt 1099511627776 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1073741824'}')
		u="${u} GB"
	elif [[ ${u_1} -lt 1125899906842624 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1099511627776'}')
		u="${u} TB"
	fi
	#echo "u=${u}"
	if [[ ${d_1} -lt 1024 ]]; then
		d="${d_1} B"
	elif [[ ${d_1} -lt 1048576 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1024'}')
		d="${d} KB"
	elif [[ ${d_1} -lt 1073741824 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1048576'}')
		d="${d} MB"
	elif [[ ${d_1} -lt 1099511627776 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1073741824'}')
		d="${d} GB"
	elif [[ ${d_1} -lt 1125899906842624 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1099511627776'}')
		d="${d} TB"
	fi
	#echo "d=${d}"
	if [[ ${transfer_enable_Used_1} -lt 1024 ]]; then
		transfer_enable_Used="${transfer_enable_Used_1} B"
	elif [[ ${transfer_enable_Used_1} -lt 1048576 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1024'}')
		transfer_enable_Used="${transfer_enable_Used} KB"
	elif [[ ${transfer_enable_Used_1} -lt 1073741824 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1048576'}')
		transfer_enable_Used="${transfer_enable_Used} MB"
	elif [[ ${transfer_enable_Used_1} -lt 1099511627776 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1073741824'}')
		transfer_enable_Used="${transfer_enable_Used} GB"
	elif [[ ${transfer_enable_Used_1} -lt 1125899906842624 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1099511627776'}')
		transfer_enable_Used="${transfer_enable_Used} TB"
	fi
	#echo "transfer_enable_Used=${transfer_enable_Used}"
	if [[ ${transfer_enable_Used_2_1} -lt 1024 ]]; then
		transfer_enable_Used_2="${transfer_enable_Used_2_1} B"
	elif [[ ${transfer_enable_Used_2_1} -lt 1048576 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1024'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} KB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1073741824 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1048576'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} MB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1099511627776 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1073741824'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} GB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1125899906842624 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1099511627776'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} TB"
	fi
	#echo "transfer_enable_Used_2=${transfer_enable_Used_2}"
}
Get_User_transfer_all(){
	if [[ ${transfer_enable_Used_233} -lt 1024 ]]; then
		transfer_enable_Used_233_2="${transfer_enable_Used_233} B"
	elif [[ ${transfer_enable_Used_233} -lt 1048576 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1024'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} KB"
	elif [[ ${transfer_enable_Used_233} -lt 1073741824 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1048576'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} MB"
	elif [[ ${transfer_enable_Used_233} -lt 1099511627776 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1073741824'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} GB"
	elif [[ ${transfer_enable_Used_233} -lt 1125899906842624 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1099511627776'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} TB"
	fi
}
urlsafe_base64(){
	date=$(echo -n "$1"|base64|sed ':a;N;s/\n/ /g;ta'|sed 's/ //g;s/=//g;s/+/-/g;s/\//_/g')
	echo -e "${date}"
}
ss_link_qr(){
	SSbase64=$(urlsafe_base64 "${method}:${password}@${ip}:${port}")
	SSurl="ss://${SSbase64}"
	SSQRcode="http://doub.pw/qr/qr.php?text=${SSurl}"
	ss_link=" SS    link : ${Green_font_prefix}${SSurl}${Font_color_suffix} \n SS  QR code : ${Green_font_prefix}${SSQRcode}${Font_color_suffix}"
}
ssr_link_qr(){
	SSRprotocol=$(echo ${protocol} | sed 's/_compatible//g')
	SSRobfs=$(echo ${obfs} | sed 's/_compatible//g')
	SSRPWDbase64=$(urlsafe_base64 "${password}")
	SSRbase64=$(urlsafe_base64 "${ip}:${port}:${SSRprotocol}:${method}:${SSRobfs}:${SSRPWDbase64}")
	SSRurl="ssr://${SSRbase64}"
	SSRQRcode="http://doub.pw/qr/qr.php?text=${SSRurl}"
	ssr_link=" SSR   link : ${Red_font_prefix}${SSRurl}${Font_color_suffix} \n SSR QR code : ${Red_font_prefix}${SSRQRcode}${Font_color_suffix} \n "
}
ss_ssr_determine(){
	protocol_suffix=`echo ${protocol} | awk -F "_" '{print $NF}'`
	obfs_suffix=`echo ${obfs} | awk -F "_" '{print $NF}'`
	if [[ ${protocol} = "origin" ]]; then
		if [[ ${obfs} = "plain" ]]; then
			ss_link_qr
			ssr_link=""
		else
			if [[ ${obfs_suffix} != "compatible" ]]; then
				ss_link=""
			else
				ss_link_qr
			fi
		fi
	else
		if [[ ${protocol_suffix} != "compatible" ]]; then
			ss_link=""
		else
			if [[ ${obfs_suffix} != "compatible" ]]; then
				if [[ ${obfs_suffix} = "plain" ]]; then
					ss_link_qr
				else
					ss_link=""
				fi
			else
				ss_link_qr
			fi
		fi
	fi
	ssr_link_qr
}
# Display configuration information
View_User(){
	SSR_installation_status
	List_port_user
	while true
	do
		echo -e "Please enter the user port to view account information"
		read -e -p "(Default: cancel):" View_user_port
		[[ -z "${View_user_port}" ]] && echo -e "Cancelled..." && exit 1
		View_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${View_user_port}"',')
		if [[ ! -z ${View_user} ]]; then
			Get_User_info "${View_user_port}"
			View_User_info
			break
		else
			echo -e "${Error} Please enter the correct port !"
		fi
	done
}
View_User_info(){
	ip=$(cat ${config_user_api_file}|grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
	[[ -z "${ip}" ]] && Get_IP
	ss_ssr_determine
	clear && echo "===================================================" && echo
	echo -e " 用户 [${user_name}] Configuration information：" && echo
	echo -e " I  P\t    : ${Green_font_prefix}${ip}${Font_color_suffix}"
	echo -e " port\t    : ${Green_font_prefix}${port}${Font_color_suffix}"
	echo -e " password\t    : ${Green_font_prefix}${password}${Font_color_suffix}"
	echo -e " encryption\t    : ${Green_font_prefix}${method}${Font_color_suffix}"
	echo -e " protocol\t    : ${Red_font_prefix}${protocol}${Font_color_suffix}"
	echo -e " Confuse\t    : ${Red_font_prefix}${obfs}${Font_color_suffix}"
	echo -e " Device limit : ${Green_font_prefix}${protocol_param}${Font_color_suffix}"
	echo -e " Single thread speed limit : ${Green_font_prefix}${speed_limit_per_con} KB/S${Font_color_suffix}"
	echo -e " Total user rate limit : ${Green_font_prefix}${speed_limit_per_user} KB/S${Font_color_suffix}"
	echo -e " Prohibited port : ${Green_font_prefix}${forbidden_port} ${Font_color_suffix}"
	echo
	echo -e " Used traffic : Upload: ${Green_font_prefix}${u}${Font_color_suffix} + download: ${Green_font_prefix}${d}${Font_color_suffix} = ${Green_font_prefix}${transfer_enable_Used_2}${Font_color_suffix}"
	echo -e " Remaining traffic : ${Green_font_prefix}${transfer_enable_Used} ${Font_color_suffix}"
	echo -e " Total user traffic : ${Green_font_prefix}${transfer_enable} ${Font_color_suffix}"
	echo -e "${ss_link}"
	echo -e "${ssr_link}"
	echo -e " ${Green_font_prefix} prompt: ${Font_color_suffix}
 In the browser, open the QR code link, you can see the QR code picture。
 Agreement and confusion behind[ _compatible ]，Refers to compatibility with the original protocol/obfuscation。"
	echo && echo "==================================================="
}
# Setting configuration information
Set_config_user(){
	echo "Please enter the user name to be set (please do not repeat it, it is used to distinguish, does not support Chinese, spaces, and an error will be reported !)"
	read -e -p "(default: abdo):" ssr_user
	[[ -z "${ssr_user}" ]] && ssr_user="doubi"
	ssr_user=$(echo "${ssr_user}"|sed 's/ //g')
	echo && echo ${Separator_1} && echo -e "	username : ${Green_font_prefix}${ssr_user}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_port(){
	while true
	do
	echo -e "Please enter the user port to be set (do not repeat, for distinction)"
	read -e -p "(default: 443):" ssr_port
	[[ -z "$ssr_port" ]] && ssr_port="2333"
	echo $((${ssr_port}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_port} -ge 1 ]] && [[ ${ssr_port} -le 65535 ]]; then
			echo && echo ${Separator_1} && echo -e "	port : ${Green_font_prefix}${ssr_port}${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Please enter the correct number(1-65535)"
		fi
	else
		echo -e "${Error} Please enter the correct number(1-65535)"
	fi
	done
}
Set_config_password(){
	echo "Please enter the user password to be set"
	read -e -p "(default: 123456):" ssr_password
	[[ -z "${ssr_password}" ]] && ssr_password="doub.io"
	echo && echo ${Separator_1} && echo -e "	password : ${Green_font_prefix}${ssr_password}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_method(){
	echo -e "Please select the user to be set Encryption method
	
 ${Green_font_prefix} 1.${Font_color_suffix} none
 ${Tip} If using auth_chain_* Series protocol, it is recommended to choose encryption method none (This series of agreements comes with RC4 encryption)，Confused
 
 ${Green_font_prefix} 2.${Font_color_suffix} rc4
 ${Green_font_prefix} 3.${Font_color_suffix} rc4-md5
 ${Green_font_prefix} 4.${Font_color_suffix} rc4-md5-6
 
 ${Green_font_prefix} 5.${Font_color_suffix} aes-128-ctr
 ${Green_font_prefix} 6.${Font_color_suffix} aes-192-ctr
 ${Green_font_prefix} 7.${Font_color_suffix} aes-256-ctr
 
 ${Green_font_prefix} 8.${Font_color_suffix} aes-128-cfb
 ${Green_font_prefix} 9.${Font_color_suffix} aes-192-cfb
 ${Green_font_prefix}10.${Font_color_suffix} aes-256-cfb
 
 ${Green_font_prefix}11.${Font_color_suffix} aes-128-cfb8
 ${Green_font_prefix}12.${Font_color_suffix} aes-192-cfb8
 ${Green_font_prefix}13.${Font_color_suffix} aes-256-cfb8
 
 ${Green_font_prefix}14.${Font_color_suffix} salsa20
 ${Green_font_prefix}15.${Font_color_suffix} chacha20
 ${Green_font_prefix}16.${Font_color_suffix} chacha20-ietf
 ${Tip} salsa20/chacha20-*Series encryption method, requires additional installation dependencies libsodium ，Otherwise it will fail to start ShadowsocksR !" && echo
	read -e -p "(default: 5. aes-256-cfb):" ssr_method
	[[ -z "${ssr_method}" ]] && ssr_method="5"
	if [[ ${ssr_method} == "1" ]]; then
		ssr_method="none"
	elif [[ ${ssr_method} == "2" ]]; then
		ssr_method="rc4"
	elif [[ ${ssr_method} == "3" ]]; then
		ssr_method="rc4-md5"
	elif [[ ${ssr_method} == "4" ]]; then
		ssr_method="rc4-md5-6"
	elif [[ ${ssr_method} == "5" ]]; then
		ssr_method="aes-128-ctr"
	elif [[ ${ssr_method} == "6" ]]; then
		ssr_method="aes-192-ctr"
	elif [[ ${ssr_method} == "7" ]]; then
		ssr_method="aes-256-ctr"
	elif [[ ${ssr_method} == "8" ]]; then
		ssr_method="aes-128-cfb"
	elif [[ ${ssr_method} == "9" ]]; then
		ssr_method="aes-192-cfb"
	elif [[ ${ssr_method} == "10" ]]; then
		ssr_method="aes-256-cfb"
	elif [[ ${ssr_method} == "11" ]]; then
		ssr_method="aes-128-cfb8"
	elif [[ ${ssr_method} == "12" ]]; then
		ssr_method="aes-192-cfb8"
	elif [[ ${ssr_method} == "13" ]]; then
		ssr_method="aes-256-cfb8"
	elif [[ ${ssr_method} == "14" ]]; then
		ssr_method="salsa20"
	elif [[ ${ssr_method} == "15" ]]; then
		ssr_method="chacha20"
	elif [[ ${ssr_method} == "16" ]]; then
		ssr_method="chacha20-ietf"
	else
		ssr_method="aes-128-ctr"
	fi
	echo && echo ${Separator_1} && echo -e "	encryption : ${Green_font_prefix}${ssr_method}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_protocol(){
	echo -e "Please select the user agreement plugin
	
 ${Green_font_prefix}1.${Font_color_suffix} origin
 ${Green_font_prefix}2.${Font_color_suffix} auth_sha1_v4
 ${Green_font_prefix}3.${Font_color_suffix} auth_aes128_md5
 ${Green_font_prefix}4.${Font_color_suffix} auth_aes128_sha1
 ${Green_font_prefix}5.${Font_color_suffix} auth_chain_a
 ${Green_font_prefix}6.${Font_color_suffix} auth_chain_b
 ${Tip} If using auth_chain_* Series protocol, it is recommended to choose encryption method none (This series of agreements comes with RC4 encryption)，Confused" && echo
	read -e -p "(default: 3. origin):" ssr_protocol
	[[ -z "${ssr_protocol}" ]] && ssr_protocol="3"
	if [[ ${ssr_protocol} == "1" ]]; then
		ssr_protocol="origin"
	elif [[ ${ssr_protocol} == "2" ]]; then
		ssr_protocol="auth_sha1_v4"
	elif [[ ${ssr_protocol} == "3" ]]; then
		ssr_protocol="auth_aes128_md5"
	elif [[ ${ssr_protocol} == "4" ]]; then
		ssr_protocol="auth_aes128_sha1"
	elif [[ ${ssr_protocol} == "5" ]]; then
		ssr_protocol="auth_chain_a"
	elif [[ ${ssr_protocol} == "6" ]]; then
		ssr_protocol="auth_chain_b"
	else
		ssr_protocol="auth_aes128_md5"
	fi
	echo && echo ${Separator_1} && echo -e "	protocol : ${Green_font_prefix}${ssr_protocol}${Font_color_suffix}" && echo ${Separator_1} && echo
	if [[ ${ssr_protocol} != "origin" ]]; then
		if [[ ${ssr_protocol} == "auth_sha1_v4" ]]; then
			read -e -p "Whether to set the protocol plug-in compatible with the original version(_compatible)？[Y/n]" ssr_protocol_yn
			[[ -z "${ssr_protocol_yn}" ]] && ssr_protocol_yn="y"
			[[ $ssr_protocol_yn == [Yy] ]] && ssr_protocol=${ssr_protocol}"_compatible"
			echo
		fi
	fi
}
Set_config_obfs(){
	echo -e "Please select the user to be set
	
 ${Green_font_prefix}1.${Font_color_suffix} plain
 ${Green_font_prefix}2.${Font_color_suffix} http_simple
 ${Green_font_prefix}3.${Font_color_suffix} http_post
 ${Green_font_prefix}4.${Font_color_suffix} random_head
 ${Green_font_prefix}5.${Font_color_suffix} tls1.2_ticket_auth
 ${Tip} If using ShadowsocksR Agent game, it is recommended to choose obfuscation compatible original version or plain Confuse，Then the client chooses plain，Otherwise it will increase the delay !
 In addition, If you choose tls1.2_ticket_auth，Then the client can choose tls1.2_ticket_fastauth，This way it can be disguised without increasing the delay !
 If you are building in popular areas such as Japan and the United States, then choose plain Confusion is less likely to be walled !" && echo
	read -e -p "(default: 5. tls1.2_ticket_auth):" ssr_obfs
	[[ -z "${ssr_obfs}" ]] && ssr_obfs="1"
	if [[ ${ssr_obfs} == "1" ]]; then
		ssr_obfs="plain"
	elif [[ ${ssr_obfs} == "2" ]]; then
		ssr_obfs="http_simple"
	elif [[ ${ssr_obfs} == "3" ]]; then
		ssr_obfs="http_post"
	elif [[ ${ssr_obfs} == "4" ]]; then
		ssr_obfs="random_head"
	elif [[ ${ssr_obfs} == "5" ]]; then
		ssr_obfs="tls1.2_ticket_auth"
	else
		ssr_obfs="plain"
	fi
	echo && echo ${Separator_1} && echo -e "	Confuse : ${Green_font_prefix}${ssr_obfs}${Font_color_suffix}" && echo ${Separator_1} && echo
	if [[ ${ssr_obfs} != "plain" ]]; then
			read -e -p "Whether to set the obfuscation plugin to be compatible with the original version(_compatible)？[Y/n]" ssr_obfs_yn
			[[ -z "${ssr_obfs_yn}" ]] && ssr_obfs_yn="y"
			[[ $ssr_obfs_yn == [Yy] ]] && ssr_obfs=${ssr_obfs}"_compatible"
			echo
	fi
}
Set_config_protocol_param(){
	while true
	do
	echo -e "Please enter the user to be set and the number of devices to be restricted (${Green_font_prefix} auth_* 系列协议 不兼容原版才有效 ${Font_color_suffix})"
	echo -e "${Tip} Device number limit: the number of clients that can be connected to each port at the same time(Multi-port mode，Each port is calculated independently)，Recommended at least 2。"
	read -e -p "(Default: unlimited):" ssr_protocol_param
	[[ -z "$ssr_protocol_param" ]] && ssr_protocol_param="" && echo && break
	echo $((${ssr_protocol_param}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_protocol_param} -ge 1 ]] && [[ ${ssr_protocol_param} -le 9999 ]]; then
			echo && echo ${Separator_1} && echo -e "	设备数限制 : ${Green_font_prefix}${ssr_protocol_param}${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Please enter the correct number(1-9999)"
		fi
	else
		echo -e "${Error} Please enter the correct number(1-9999)"
	fi
	done
}
Set_config_speed_limit_per_con(){
	while true
	do
	echo -e "请输入要设置的用户 单线程 限速上限(单位：KB/S)"
	echo -e "${Tip} 单线程限速：每个端口 单线程的限速上限，多线程即无效。"
	read -e -p "(默认: 无限):" ssr_speed_limit_per_con
	[[ -z "$ssr_speed_limit_per_con" ]] && ssr_speed_limit_per_con=0 && echo && break
	echo $((${ssr_speed_limit_per_con}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_speed_limit_per_con} -ge 1 ]] && [[ ${ssr_speed_limit_per_con} -le 131072 ]]; then
			echo && echo ${Separator_1} && echo -e "	单线程限速 : ${Green_font_prefix}${ssr_speed_limit_per_con} KB/S${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} 请输入正确的数字(1-131072)"
		fi
	else
		echo -e "${Error} 请输入正确的数字(1-131072)"
	fi
	done
}
Set_config_speed_limit_per_user(){
	while true
	do
	echo
	echo -e "请输入要设置的用户 总速度 限速上限(单位：KB/S)"
	echo -e "${Tip} 端口总限速：每个端口 总速度 限速上限，单个端口整体限速。"
	read -e -p "(默认: 无限):" ssr_speed_limit_per_user
	[[ -z "$ssr_speed_limit_per_user" ]] && ssr_speed_limit_per_user=0 && echo && break
	echo $((${ssr_speed_limit_per_user}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_speed_limit_per_user} -ge 1 ]] && [[ ${ssr_speed_limit_per_user} -le 131072 ]]; then
			echo && echo ${Separator_1} && echo -e "	用户总限速 : ${Green_font_prefix}${ssr_speed_limit_per_user} KB/S${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} 请输入正确的数字(1-131072)"
		fi
	else
		echo -e "${Error} 请输入正确的数字(1-131072)"
	fi
	done
}
Set_config_transfer(){
	while true
	do
	echo
	echo -e "请输入要设置的用户 可使用的总流量上限(单位: GB, 1-838868 GB)"
	read -e -p "(默认: 无限):" ssr_transfer
	[[ -z "$ssr_transfer" ]] && ssr_transfer="838868" && echo && break
	echo $((${ssr_transfer}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_transfer} -ge 1 ]] && [[ ${ssr_transfer} -le 838868 ]]; then
			echo && echo ${Separator_1} && echo -e "	用户总流量 : ${Green_font_prefix}${ssr_transfer} GB${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} 请输入正确的数字(1-838868)"
		fi
	else
		echo -e "${Error} 请输入正确的数字(1-838868)"
	fi
	done
}
Set_config_forbid(){
	echo "请输入要设置的用户 禁止访问的端口"
	echo -e "${Tip} 禁止的端口：例如不允许访问 25端口，用户就无法通过SSR代理访问 邮件端口25了，如果禁止了 80,443 那么用户将无法正常访问 http/https 网站。
封禁单个端口格式: 25
封禁多个端口格式: 23,465
封禁  端口段格式: 233-266
封禁多种格式端口: 25,465,233-666 (不带冒号:)"
	read -e -p "(默认为空 不禁止访问任何端口):" ssr_forbid
	[[ -z "${ssr_forbid}" ]] && ssr_forbid=""
	echo && echo ${Separator_1} && echo -e "	禁止的端口 : ${Green_font_prefix}${ssr_forbid}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_enable(){
	user_total=$(echo $((${user_total}-1)))
	for((integer = 0; integer <= ${user_total}; integer++))
	do
		echo -e "integer=${integer}"
		port_jq=$(${jq_file} ".[${integer}].port" "${config_user_mudb_file}")
		echo -e "port_jq=${port_jq}"
		if [[ "${ssr_port}" == "${port_jq}" ]]; then
			enable=$(${jq_file} ".[${integer}].enable" "${config_user_mudb_file}")
			echo -e "enable=${enable}"
			[[ "${enable}" == "null" ]] && echo -e "${Error} 获取当前端口[${ssr_port}]的禁用状态失败 !" && exit 1
			ssr_port_num=$(cat "${config_user_mudb_file}"|grep -n '"port": '${ssr_port}','|awk -F ":" '{print $1}')
			echo -e "ssr_port_num=${ssr_port_num}"
			[[ "${ssr_port_num}" == "null" ]] && echo -e "${Error} 获取当前端口[${ssr_port}]的行数失败 !" && exit 1
			ssr_enable_num=$(echo $((${ssr_port_num}-5)))
			echo -e "ssr_enable_num=${ssr_enable_num}"
			break
		fi
	done
	if [[ "${enable}" == "1" ]]; then
		echo -e "端口 [${ssr_port}] 的账号状态为：${Green_font_prefix}启用${Font_color_suffix} , 是否切换为 ${Red_font_prefix}禁用${Font_color_suffix} ?[Y/n]"
		read -e -p "(默认: Y):" ssr_enable_yn
		[[ -z "${ssr_enable_yn}" ]] && ssr_enable_yn="y"
		if [[ "${ssr_enable_yn}" == [Yy] ]]; then
			ssr_enable="0"
		else
			echo "取消..." && exit 0
		fi
	elif [[ "${enable}" == "0" ]]; then
		echo -e "端口 [${ssr_port}] 的账号状态为：${Green_font_prefix}禁用${Font_color_suffix} , 是否切换为 ${Red_font_prefix}启用${Font_color_suffix} ?[Y/n]"
		read -e -p "(默认: Y):" ssr_enable_yn
		[[ -z "${ssr_enable_yn}" ]] && ssr_enable_yn = "y"
		if [[ "${ssr_enable_yn}" == [Yy] ]]; then
			ssr_enable="1"
		else
			echo "取消..." && exit 0
		fi
	else
		echo -e "${Error} 当前端口的禁用状态异常[${enable}] !" && exit 1
	fi
}
Set_user_api_server_pub_addr(){
	addr=$1
	if [[ "${addr}" == "Modify" ]]; then
		server_pub_addr=$(cat ${config_user_api_file}|grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
		if [[ -z ${server_pub_addr} ]]; then
			echo -e "${Error} 获取当前配置的 服务器IP或域名失败！" && exit 1
		else
			echo -e "${Info} 当前配置的服务器IP或域名为： ${Green_font_prefix}${server_pub_addr}${Font_color_suffix}"
		fi
	fi
	echo "请输入用户配置中要显示的 服务器IP或域名 (当服务器有多个IP时，可以指定用户配置中显示的IP或者域名)"
	read -e -p "(默认自动检测外网IP):" ssr_server_pub_addr
	if [[ -z "${ssr_server_pub_addr}" ]]; then
		Get_IP
		if [[ ${ip} == "VPS_IP" ]]; then
			while true
			do
			read -e -p "${Error} 自动检测外网IP失败，请手动输入服务器IP或域名" ssr_server_pub_addr
			if [[ -z "$ssr_server_pub_addr" ]]; then
				echo -e "${Error} 不能为空！"
			else
				break
			fi
			done
		else
			ssr_server_pub_addr="${ip}"
		fi
	fi
	echo && echo ${Separator_1} && echo -e "	IP或域名 : ${Green_font_prefix}${ssr_server_pub_addr}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_all(){
	lal=$1
	if [[ "${lal}" == "Modify" ]]; then
		Set_config_password
		Set_config_method
		Set_config_protocol
		Set_config_obfs
		Set_config_protocol_param
		Set_config_speed_limit_per_con
		Set_config_speed_limit_per_user
		Set_config_transfer
		Set_config_forbid
	else
		Set_config_user
		Set_config_port
		Set_config_password
		Set_config_method
		Set_config_protocol
		Set_config_obfs
		Set_config_protocol_param
		Set_config_speed_limit_per_con
		Set_config_speed_limit_per_user
		Set_config_transfer
		Set_config_forbid
	fi
}
# 修改 配置信息
Modify_config_password(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -k "${ssr_password}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} 用户密码修改失败 ${Green_font_prefix}[端口: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} 用户密码修改成功 ${Green_font_prefix}[端口: ${ssr_port}]${Font_color_suffix} (注意：可能需要十秒左右才会应用最新配置)"
	fi
}
Modify_config_method(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -m "${ssr_method}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} 用户加密方式修改失败 ${Green_font_prefix}[端口: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} 用户加密方式修改成功 ${Green_font_prefix}[端口: ${ssr_port}]${Font_color_suffix} (注意：可能需要十秒左右才会应用最新配置)"
	fi
}
Modify_config_protocol(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -O "${ssr_protocol}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} 用户协议修改失败 ${Green_font_prefix}[端口: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} 用户协议修改成功 ${Green_font_prefix}[端口: ${ssr_port}]${Font_color_suffix} (注意：可能需要十秒左右才会应用最新配置)"
	fi
}
Modify_config_obfs(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -o "${ssr_obfs}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} 用户混淆修改失败 ${Green_font_prefix}[端口: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} 用户混淆修改成功 ${Green_font_prefix}[端口: ${ssr_port}]${Font_color_suffix} (注意：可能需要十秒左右才会应用最新配置)"
	fi
}
Modify_config_protocol_param(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -G "${ssr_protocol_param}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} 用户协议参数(设备数限制)修改失败 ${Green_font_prefix}[端口: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} 用户议参数(设备数限制)修改成功 ${Green_font_prefix}[端口: ${ssr_port}]${Font_color_suffix} (注意：可能需要十秒左右才会应用最新配置)"
	fi
}
Modify_config_speed_limit_per_con(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -s "${ssr_speed_limit_per_con}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} 用户单线程限速修改失败 ${Green_font_prefix}[端口: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} 用户单线程限速修改成功 ${Green_font_prefix}[端口: ${ssr_port}]${Font_color_suffix} (注意：可能需要十秒左右才会应用最新配置)"
	fi
}
Modify_config_speed_limit_per_user(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -S "${ssr_speed_limit_per_user}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} 用户端口总限速修改失败 ${Green_font_prefix}[端口: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} 用户端口总限速修改成功 ${Green_font_prefix}[端口: ${ssr_port}]${Font_color_suffix} (注意：可能需要十秒左右才会应用最新配置)"
	fi
}
Modify_config_connect_verbose_info(){
	sed -i 's/"connect_verbose_info": '"$(echo ${connect_verbose_info})"',/"connect_verbose_info": '"$(echo ${ssr_connect_verbose_info})"',/g' ${config_user_file}
}
Modify_config_transfer(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -t "${ssr_transfer}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} 用户总流量修改失败 ${Green_font_prefix}[端口: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} 用户总流量修改成功 ${Green_font_prefix}[端口: ${ssr_port}]${Font_color_suffix} (注意：可能需要十秒左右才会应用最新配置)"
	fi
}
Modify_config_forbid(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -f "${ssr_forbid}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} 用户禁止访问端口修改失败 ${Green_font_prefix}[端口: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} 用户禁止访问端口修改成功 ${Green_font_prefix}[端口: ${ssr_port}]${Font_color_suffix} (注意：可能需要十秒左右才会应用最新配置)"
	fi
}
Modify_config_enable(){
	sed -i "${ssr_enable_num}"'s/"enable": '"$(echo ${enable})"',/"enable": '"$(echo ${ssr_enable})"',/' ${config_user_mudb_file}
}
Modify_user_api_server_pub_addr(){
	sed -i "s/SERVER_PUB_ADDR = '${server_pub_addr}'/SERVER_PUB_ADDR = '${ssr_server_pub_addr}'/" ${config_user_api_file}
}
Modify_config_all(){
	Modify_config_password
	Modify_config_method
	Modify_config_protocol
	Modify_config_obfs
	Modify_config_protocol_param
	Modify_config_speed_limit_per_con
	Modify_config_speed_limit_per_user
	Modify_config_transfer
	Modify_config_forbid
}
Check_python(){
	python_ver=`python -h`
	if [[ -z ${python_ver} ]]; then
		echo -e "${Info} 没有安装Python，开始安装..."
		if [[ ${release} == "centos" ]]; then
			yum install -y python
		else
			apt-get install -y python
		fi
	fi
}
Centos_yum(){
	yum update
	cat /etc/redhat-release |grep 7\..*|grep -i centos>/dev/null
	if [[ $? = 0 ]]; then
		yum install -y vim unzip crond net-tools
	else
		yum install -y vim unzip crond
	fi
}
Debian_apt(){
	apt-get update
	cat /etc/issue |grep 9\..*>/dev/null
	if [[ $? = 0 ]]; then
		apt-get install -y vim unzip cron net-tools
	else
		apt-get install -y vim unzip cron
	fi
}
# 下载 ShadowsocksR
Download_SSR(){
	cd "/usr/local"
	wget -N --no-check-certificate "https://github.com/ToyoDAdoubiBackup/shadowsocksr/archive/manyuser.zip"
	#git config --global http.sslVerify false
	#env GIT_SSL_NO_VERIFY=true git clone -b manyuser https://github.com/ToyoDAdoubiBackup/shadowsocksr.git
	#[[ ! -e ${ssr_folder} ]] && echo -e "${Error} ShadowsocksR服务端 下载失败 !" && exit 1
	[[ ! -e "manyuser.zip" ]] && echo -e "${Error} ShadowsocksR服务端 压缩包 下载失败 !" && rm -rf manyuser.zip && exit 1
	unzip "manyuser.zip"
	[[ ! -e "/usr/local/shadowsocksr-manyuser/" ]] && echo -e "${Error} ShadowsocksR服务端 解压失败 !" && rm -rf manyuser.zip && exit 1
	mv "/usr/local/shadowsocksr-manyuser/" "/usr/local/shadowsocksr/"
	[[ ! -e "/usr/local/shadowsocksr/" ]] && echo -e "${Error} ShadowsocksR服务端 重命名失败 !" && rm -rf manyuser.zip && rm -rf "/usr/local/shadowsocksr-manyuser/" && exit 1
	rm -rf manyuser.zip
	cd "shadowsocksr"
	cp "${ssr_folder}/config.json" "${config_user_file}"
	cp "${ssr_folder}/mysql.json" "${ssr_folder}/usermysql.json"
	cp "${ssr_folder}/apiconfig.py" "${config_user_api_file}"
	[[ ! -e ${config_user_api_file} ]] && echo -e "${Error} ShadowsocksR服务端 apiconfig.py 复制失败 !" && exit 1
	sed -i "s/API_INTERFACE = 'sspanelv2'/API_INTERFACE = 'mudbjson'/" ${config_user_api_file}
	server_pub_addr="127.0.0.1"
	Modify_user_api_server_pub_addr
	#sed -i "s/SERVER_PUB_ADDR = '127.0.0.1'/SERVER_PUB_ADDR = '${ip}'/" ${config_user_api_file}
	sed -i 's/ \/\/ only works under multi-user mode//g' "${config_user_file}"
	echo -e "${Info} ShadowsocksR服务端 下载完成 !"
}
Service_SSR(){
	if [[ ${release} = "centos" ]]; then
		if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/service/ssrmu_centos -O /etc/init.d/ssrmu; then
			echo -e "${Error} ShadowsocksR服务 管理脚本下载失败 !" && exit 1
		fi
		chmod +x /etc/init.d/ssrmu
		chkconfig --add ssrmu
		chkconfig ssrmu on
	else
		if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/service/ssrmu_debian -O /etc/init.d/ssrmu; then
			echo -e "${Error} ShadowsocksR服务 管理脚本下载失败 !" && exit 1
		fi
		chmod +x /etc/init.d/ssrmu
		update-rc.d -f ssrmu defaults
	fi
	echo -e "${Info} ShadowsocksR服务 管理脚本下载完成 !"
}
# 安装 JQ解析器
JQ_install(){
	if [[ ! -e ${jq_file} ]]; then
		cd "${ssr_folder}"
		if [[ ${bit} = "x86_64" ]]; then
			mv "jq-linux64" "jq"
			#wget --no-check-certificate "https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux64" -O ${jq_file}
		else
			mv "jq-linux32" "jq"
			#wget --no-check-certificate "https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux32" -O ${jq_file}
		fi
		[[ ! -e ${jq_file} ]] && echo -e "${Error} JQ解析器 重命名失败，请检查 !" && exit 1
		chmod +x ${jq_file}
		echo -e "${Info} JQ解析器 安装完成，继续..." 
	else
		echo -e "${Info} JQ解析器 已安装，继续..."
	fi
}
# 安装 依赖
Installation_dependency(){
	if [[ ${release} == "centos" ]]; then
		Centos_yum
	else
		Debian_apt
	fi
	[[ ! -e "/usr/bin/unzip" ]] && echo -e "${Error} 依赖 unzip(解压压缩包) 安装失败，多半是软件包源的问题，请检查 !" && exit 1
	Check_python
	#echo "nameserver 8.8.8.8" > /etc/resolv.conf
	#echo "nameserver 8.8.4.4" >> /etc/resolv.conf
	\cp -f /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
	if [[ ${release} == "centos" ]]; then
		/etc/init.d/crond restart
	else
		/etc/init.d/cron restart
	fi
}
Install_SSR(){
	check_root
	[[ -e ${ssr_folder} ]] && echo -e "${Error} ShadowsocksR 文件夹已存在，请检查( 如安装失败或者存在旧版本，请先卸载 ) !" && exit 1
	echo -e "${Info} 开始设置 ShadowsocksR账号配置..."
	Set_user_api_server_pub_addr
	Set_config_all
	echo -e "${Info} 开始安装/配置 ShadowsocksR依赖..."
	Installation_dependency
	echo -e "${Info} 开始下载/安装 ShadowsocksR文件..."
	Download_SSR
	echo -e "${Info} 开始下载/安装 ShadowsocksR服务脚本(init)..."
	Service_SSR
	echo -e "${Info} 开始下载/安装 JSNO解析器 JQ..."
	JQ_install
	echo -e "${Info} 开始添加初始用户..."
	Add_port_user "install"
	echo -e "${Info} 开始设置 iptables防火墙..."
	Set_iptables
	echo -e "${Info} 开始添加 iptables防火墙规则..."
	Add_iptables
	echo -e "${Info} 开始保存 iptables防火墙规则..."
	Save_iptables
	echo -e "${Info} 所有步骤 安装完毕，开始启动 ShadowsocksR服务端..."
	Start_SSR
	Get_User_info "${ssr_port}"
	View_User_info
}
Update_SSR(){
	SSR_installation_status
	echo -e "因破娃暂停更新ShadowsocksR服务端，所以此功能临时禁用。"
	#cd ${ssr_folder}
	#git pull
	#Restart_SSR
}
Uninstall_SSR(){
	[[ ! -e ${ssr_folder} ]] && echo -e "${Error} 没有安装 ShadowsocksR，请检查 !" && exit 1
	echo "确定要 卸载ShadowsocksR？[y/N]" && echo
	read -e -p "(默认: n):" unyn
	[[ -z ${unyn} ]] && unyn="n"
	if [[ ${unyn} == [Yy] ]]; then
		check_pid
		[[ ! -z "${PID}" ]] && kill -9 ${PID}
		user_info=$(python mujson_mgr.py -l)
		user_total=$(echo "${user_info}"|wc -l)
		if [[ ! -z ${user_info} ]]; then
			for((integer = 1; integer <= ${user_total}; integer++))
			do
				port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
				Del_iptables
			done
			Save_iptables
		fi
		if [[ ! -z $(crontab -l | grep "ssrmu.sh") ]]; then
			crontab_monitor_ssr_cron_stop
			Clear_transfer_all_cron_stop
		fi
		if [[ ${release} = "centos" ]]; then
			chkconfig --del ssrmu
		else
			update-rc.d -f ssrmu remove
		fi
		rm -rf ${ssr_folder} && rm -rf /etc/init.d/ssrmu
		echo && echo " ShadowsocksR 卸载完成 !" && echo
	else
		echo && echo " 卸载已取消..." && echo
	fi
}
Check_Libsodium_ver(){
	echo -e "${Info} 开始获取 libsodium 最新版本..."
	Libsodiumr_ver=$(wget -qO- "https://github.com/jedisct1/libsodium/tags"|grep "/jedisct1/libsodium/releases/tag/"|head -1|sed -r 's/.*tag\/(.+)\">.*/\1/')
	[[ -z ${Libsodiumr_ver} ]] && Libsodiumr_ver=${Libsodiumr_ver_backup}
	echo -e "${Info} libsodium 最新版本为 ${Green_font_prefix}${Libsodiumr_ver}${Font_color_suffix} !"
}
Install_Libsodium(){
	if [[ -e ${Libsodiumr_file} ]]; then
		echo -e "${Error} libsodium 已安装 , 是否覆盖安装(更新)？[y/N]"
		read -e -p "(默认: n):" yn
		[[ -z ${yn} ]] && yn="n"
		if [[ ${yn} == [Nn] ]]; then
			echo "已取消..." && exit 1
		fi
	else
		echo -e "${Info} libsodium 未安装，开始安装..."
	fi
	Check_Libsodium_ver
	if [[ ${release} == "centos" ]]; then
		yum update
		echo -e "${Info} 安装依赖..."
		yum -y groupinstall "Development Tools"
		echo -e "${Info} 下载..."
		wget  --no-check-certificate -N "https://github.com/jedisct1/libsodium/releases/download/${Libsodiumr_ver}-RELEASE/libsodium-${Libsodiumr_ver}.tar.gz"
		echo -e "${Info} 解压..."
		tar -xzf libsodium-${Libsodiumr_ver}.tar.gz && cd libsodium-${Libsodiumr_ver}
		echo -e "${Info} 编译安装..."
		./configure --disable-maintainer-mode && make -j2 && make install
		echo /usr/local/lib > /etc/ld.so.conf.d/usr_local_lib.conf
	else
		apt-get update
		echo -e "${Info} 安装依赖..."
		apt-get install -y build-essential
		echo -e "${Info} 下载..."
		wget  --no-check-certificate -N "https://github.com/jedisct1/libsodium/releases/download/${Libsodiumr_ver}-RELEASE/libsodium-${Libsodiumr_ver}.tar.gz"
		echo -e "${Info} 解压..."
		tar -xzf libsodium-${Libsodiumr_ver}.tar.gz && cd libsodium-${Libsodiumr_ver}
		echo -e "${Info} 编译安装..."
		./configure --disable-maintainer-mode && make -j2 && make install
	fi
	ldconfig
	cd .. && rm -rf libsodium-${Libsodiumr_ver}.tar.gz && rm -rf libsodium-${Libsodiumr_ver}
	[[ ! -e ${Libsodiumr_file} ]] && echo -e "${Error} libsodium 安装失败 !" && exit 1
	echo && echo -e "${Info} libsodium 安装成功 !" && echo
}
# 显示 连接信息
debian_View_user_connection_info(){
	format_1=$1
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} 没有发现 用户，请检查 !" && exit 1
	IP_total=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" |wc -l`
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_IP_1=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |grep ":${user_port} " |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`
		if [[ -z ${user_IP_1} ]]; then
			user_IP_total="0"
		else
			user_IP_total=`echo -e "${user_IP_1}"|wc -l`
			if [[ ${format_1} == "IP_address" ]]; then
				get_IP_address
			else
				user_IP=`echo -e "\n${user_IP_1}"`
			fi
		fi
		user_info_233=$(python mujson_mgr.py -l|grep -w "${user_port}"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		user_list_all=${user_list_all}"用户名: ${Green_font_prefix}"${user_info_233}"${Font_color_suffix}\t 端口: ${Green_font_prefix}"${user_port}"${Font_color_suffix}\t 链接IP总数: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\t 当前链接IP: ${Green_font_prefix}${user_IP}${Font_color_suffix}\n"
		user_IP=""
	done
	echo -e "用户总数: ${Green_background_prefix} "${user_total}" ${Font_color_suffix} 链接IP总数: ${Green_background_prefix} "${IP_total}" ${Font_color_suffix} "
	echo -e "${user_list_all}"
}
centos_View_user_connection_info(){
	format_1=$1
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} 没有发现 用户，请检查 !" && exit 1
	IP_total=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp' | grep '::ffff:' |awk '{print $5}' |awk -F ":" '{print $4}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" |wc -l`
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_IP_1=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp' |grep ":${user_port} "|grep '::ffff:' |awk '{print $5}' |awk -F ":" '{print $4}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`
		if [[ -z ${user_IP_1} ]]; then
			user_IP_total="0"
		else
			user_IP_total=`echo -e "${user_IP_1}"|wc -l`
			if [[ ${format_1} == "IP_address" ]]; then
				get_IP_address
			else
				user_IP=`echo -e "\n${user_IP_1}"`
			fi
		fi
		user_info_233=$(python mujson_mgr.py -l|grep -w "${user_port}"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		user_list_all=${user_list_all}"用户名: ${Green_font_prefix}"${user_info_233}"${Font_color_suffix}\t 端口: ${Green_font_prefix}"${user_port}"${Font_color_suffix}\t 链接IP总数: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\t 当前链接IP: ${Green_font_prefix}${user_IP}${Font_color_suffix}\n"
		user_IP=""
	done
	echo -e "用户总数: ${Green_background_prefix} "${user_total}" ${Font_color_suffix} 链接IP总数: ${Green_background_prefix} "${IP_total}" ${Font_color_suffix} "
	echo -e "${user_list_all}"
}
View_user_connection_info(){
	SSR_installation_status
	echo && echo -e "请选择要显示的格式：
 ${Green_font_prefix}1.${Font_color_suffix} 显示 IP 格式
 ${Green_font_prefix}2.${Font_color_suffix} 显示 IP+IP归属地 格式" && echo
	read -e -p "(默认: 1):" ssr_connection_info
	[[ -z "${ssr_connection_info}" ]] && ssr_connection_info="1"
	if [[ ${ssr_connection_info} == "1" ]]; then
		View_user_connection_info_1 ""
	elif [[ ${ssr_connection_info} == "2" ]]; then
		echo -e "${Tip} 检测IP归属地(ipip.net)，如果IP较多，可能时间会比较长..."
		View_user_connection_info_1 "IP_address"
	else
		echo -e "${Error} 请输入正确的数字(1-2)" && exit 1
	fi
}
View_user_connection_info_1(){
	format=$1
	if [[ ${release} = "centos" ]]; then
		cat /etc/redhat-release |grep 7\..*|grep -i centos>/dev/null
		if [[ $? = 0 ]]; then
			debian_View_user_connection_info "$format"
		else
			centos_View_user_connection_info "$format"
		fi
	else
		debian_View_user_connection_info "$format"
	fi
}
get_IP_address(){
	#echo "user_IP_1=${user_IP_1}"
	if [[ ! -z ${user_IP_1} ]]; then
	#echo "user_IP_total=${user_IP_total}"
		for((integer_1 = ${user_IP_total}; integer_1 >= 1; integer_1--))
		do
			IP=`echo "${user_IP_1}" |sed -n "$integer_1"p`
			#echo "IP=${IP}"
			IP_address=`wget -qO- -t1 -T2 http://freeapi.ipip.net/${IP}|sed 's/\"//g;s/,//g;s/\[//g;s/\]//g'`
			#echo "IP_address=${IP_address}"
			user_IP="${user_IP}\n${IP}(${IP_address})"
			#echo "user_IP=${user_IP}"
			sleep 1s
		done
	fi
}
# 修改 用户配置
Modify_port(){
	List_port_user
	while true
	do
		echo -e "请输入要修改的用户 端口"
		read -e -p "(默认: 取消):" ssr_port
		[[ -z "${ssr_port}" ]] && echo -e "已取消..." && exit 1
		Modify_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${ssr_port}"',')
		if [[ ! -z ${Modify_user} ]]; then
			break
		else
			echo -e "${Error} 请输入正确的端口 !"
		fi
	done
}
Modify_Config(){
	SSR_installation_status
	echo && echo -e "你要做什么？
 ${Green_font_prefix}1.${Font_color_suffix}  添加 用户配置
 ${Green_font_prefix}2.${Font_color_suffix}  删除 用户配置
————— 修改 用户配置 —————
 ${Green_font_prefix}3.${Font_color_suffix}  修改 用户密码
 ${Green_font_prefix}4.${Font_color_suffix}  修改 加密方式
 ${Green_font_prefix}5.${Font_color_suffix}  修改 协议插件
 ${Green_font_prefix}6.${Font_color_suffix}  修改 混淆插件
 ${Green_font_prefix}7.${Font_color_suffix}  修改 设备数限制
 ${Green_font_prefix}8.${Font_color_suffix}  修改 单线程限速
 ${Green_font_prefix}9.${Font_color_suffix}  修改 用户总限速
 ${Green_font_prefix}10.${Font_color_suffix} 修改 用户总流量
 ${Green_font_prefix}11.${Font_color_suffix} 修改 用户禁用端口
 ${Green_font_prefix}12.${Font_color_suffix} 修改 全部配置
————— 其他 —————
 ${Green_font_prefix}13.${Font_color_suffix} 修改 用户配置中显示的IP或域名
 
 ${Tip} 用户的用户名和端口是无法修改，如果需要修改请使用脚本的 手动修改功能 !" && echo
	read -e -p "(默认: 取消):" ssr_modify
	[[ -z "${ssr_modify}" ]] && echo "已取消..." && exit 1
	if [[ ${ssr_modify} == "1" ]]; then
		Add_port_user
	elif [[ ${ssr_modify} == "2" ]]; then
		Del_port_user
	elif [[ ${ssr_modify} == "3" ]]; then
		Modify_port
		Set_config_password
		Modify_config_password
	elif [[ ${ssr_modify} == "4" ]]; then
		Modify_port
		Set_config_method
		Modify_config_method
	elif [[ ${ssr_modify} == "5" ]]; then
		Modify_port
		Set_config_protocol
		Modify_config_protocol
	elif [[ ${ssr_modify} == "6" ]]; then
		Modify_port
		Set_config_obfs
		Modify_config_obfs
	elif [[ ${ssr_modify} == "7" ]]; then
		Modify_port
		Set_config_protocol_param
		Modify_config_protocol_param
	elif [[ ${ssr_modify} == "8" ]]; then
		Modify_port
		Set_config_speed_limit_per_con
		Modify_config_speed_limit_per_con
	elif [[ ${ssr_modify} == "9" ]]; then
		Modify_port
		Set_config_speed_limit_per_user
		Modify_config_speed_limit_per_user
	elif [[ ${ssr_modify} == "10" ]]; then
		Modify_port
		Set_config_transfer
		Modify_config_transfer
	elif [[ ${ssr_modify} == "11" ]]; then
		Modify_port
		Set_config_forbid
		Modify_config_forbid
	elif [[ ${ssr_modify} == "12" ]]; then
		Modify_port
		Set_config_all "Modify"
		Modify_config_all
	elif [[ ${ssr_modify} == "13" ]]; then
		Set_user_api_server_pub_addr "Modify"
		Modify_user_api_server_pub_addr
	else
		echo -e "${Error} 请输入正确的数字(1-13)" && exit 1
	fi
}
List_port_user(){
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} 没有发现 用户，请检查 !" && exit 1
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_username=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		Get_User_transfer "${user_port}"
		transfer_enable_Used_233=$(echo $((${transfer_enable_Used_233}+${transfer_enable_Used_2_1})))
		user_list_all=${user_list_all}"用户名: ${Green_font_prefix} "${user_username}"${Font_color_suffix}\t 端口: ${Green_font_prefix}"${user_port}"${Font_color_suffix}\t 流量使用情况(已用+剩余=总): ${Green_font_prefix}${transfer_enable_Used_2}${Font_color_suffix} + ${Green_font_prefix}${transfer_enable_Used}${Font_color_suffix} = ${Green_font_prefix}${transfer_enable}${Font_color_suffix}\n"
	done
	Get_User_transfer_all
	echo && echo -e "=== 用户总数 ${Green_background_prefix} "${user_total}" ${Font_color_suffix}"
	echo -e ${user_list_all}
	echo -e "=== 当前所有用户已使用流量总和: ${Green_background_prefix} ${transfer_enable_Used_233_2} ${Font_color_suffix}\n"
}
Add_port_user(){
	lalal=$1
	if [[ "$lalal" == "install" ]]; then
		match_add=$(python mujson_mgr.py -a -u "${ssr_user}" -p "${ssr_port}" -k "${ssr_password}" -m "${ssr_method}" -O "${ssr_protocol}" -G "${ssr_protocol_param}" -o "${ssr_obfs}" -s "${ssr_speed_limit_per_con}" -S "${ssr_speed_limit_per_user}" -t "${ssr_transfer}" -f "${ssr_forbid}"|grep -w "add user info")
	else
		while true
		do
			Set_config_all
			match_port=$(python mujson_mgr.py -l|grep -w "port ${ssr_port}$")
			[[ ! -z "${match_port}" ]] && echo -e "${Error} 该端口 [${ssr_port}] 已存在，请勿重复添加 !" && exit 1
			match_username=$(python mujson_mgr.py -l|grep -w "user \[${ssr_user}]")
			[[ ! -z "${match_username}" ]] && echo -e "${Error} 该用户名 [${ssr_user}] 已存在，请勿重复添加 !" && exit 1
			match_add=$(python mujson_mgr.py -a -u "${ssr_user}" -p "${ssr_port}" -k "${ssr_password}" -m "${ssr_method}" -O "${ssr_protocol}" -G "${ssr_protocol_param}" -o "${ssr_obfs}" -s "${ssr_speed_limit_per_con}" -S "${ssr_speed_limit_per_user}" -t "${ssr_transfer}" -f "${ssr_forbid}"|grep -w "add user info")
			if [[ -z "${match_add}" ]]; then
				echo -e "${Error} 用户添加失败 ${Green_font_prefix}[用户名: ${ssr_user} , 端口: ${ssr_port}]${Font_color_suffix} "
				break
			else
				Add_iptables
				Save_iptables
				echo -e "${Info} 用户添加成功 ${Green_font_prefix}[用户名: ${ssr_user} , 端口: ${ssr_port}]${Font_color_suffix} "
				echo
				read -e -p "是否继续 添加用户配置？[Y/n]:" addyn
				[[ -z ${addyn} ]] && addyn="y"
				if [[ ${addyn} == [Nn] ]]; then
					Get_User_info "${ssr_port}"
					View_User_info
					break
				else
					echo -e "${Info} 继续 添加用户配置..."
				fi
			fi
		done
	fi
}
Del_port_user(){
	List_port_user
	while true
	do
		echo -e "请输入要删除的用户 端口"
		read -e -p "(默认: 取消):" del_user_port
		[[ -z "${del_user_port}" ]] && echo -e "已取消..." && exit 1
		del_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${del_user_port}"',')
		if [[ ! -z ${del_user} ]]; then
			port=${del_user_port}
			match_del=$(python mujson_mgr.py -d -p "${del_user_port}"|grep -w "delete user ")
			if [[ -z "${match_del}" ]]; then
				echo -e "${Error} 用户删除失败 ${Green_font_prefix}[端口: ${del_user_port}]${Font_color_suffix} "
			else
				Del_iptables
				Save_iptables
				echo -e "${Info} 用户删除成功 ${Green_font_prefix}[端口: ${del_user_port}]${Font_color_suffix} "
			fi
			break
		else
			echo -e "${Error} 请输入正确的端口 !"
		fi
	done
}
Manually_Modify_Config(){
	SSR_installation_status
	vi ${config_user_mudb_file}
	echo "是否现在重启ShadowsocksR？[Y/n]" && echo
	read -e -p "(默认: y):" yn
	[[ -z ${yn} ]] && yn="y"
	if [[ ${yn} == [Yy] ]]; then
		Restart_SSR
	fi
}
Clear_transfer(){
	SSR_installation_status
	echo && echo -e "你要做什么？
 ${Green_font_prefix}1.${Font_color_suffix}  清零 单个用户已使用流量
 ${Green_font_prefix}2.${Font_color_suffix}  清零 所有用户已使用流量(不可挽回)
 ${Green_font_prefix}3.${Font_color_suffix}  启动 定时所有用户流量清零
 ${Green_font_prefix}4.${Font_color_suffix}  停止 定时所有用户流量清零
 ${Green_font_prefix}5.${Font_color_suffix}  修改 定时所有用户流量清零" && echo
	read -e -p "(默认: 取消):" ssr_modify
	[[ -z "${ssr_modify}" ]] && echo "已取消..." && exit 1
	if [[ ${ssr_modify} == "1" ]]; then
		Clear_transfer_one
	elif [[ ${ssr_modify} == "2" ]]; then
		echo "确定要 清零 所有用户已使用流量？[y/N]" && echo
		read -e -p "(默认: n):" yn
		[[ -z ${yn} ]] && yn="n"
		if [[ ${yn} == [Yy] ]]; then
			Clear_transfer_all
		else
			echo "取消..."
		fi
	elif [[ ${ssr_modify} == "3" ]]; then
		check_crontab
		Set_crontab
		Clear_transfer_all_cron_start
	elif [[ ${ssr_modify} == "4" ]]; then
		check_crontab
		Clear_transfer_all_cron_stop
	elif [[ ${ssr_modify} == "5" ]]; then
		check_crontab
		Clear_transfer_all_cron_modify
	else
		echo -e "${Error} 请输入正确的数字(1-5)" && exit 1
	fi
}
Clear_transfer_one(){
	List_port_user
	while true
	do
		echo -e "请输入要清零已使用流量的用户 端口"
		read -e -p "(默认: 取消):" Clear_transfer_user_port
		[[ -z "${Clear_transfer_user_port}" ]] && echo -e "已取消..." && exit 1
		Clear_transfer_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${Clear_transfer_user_port}"',')
		if [[ ! -z ${Clear_transfer_user} ]]; then
			match_clear=$(python mujson_mgr.py -c -p "${Clear_transfer_user_port}"|grep -w "clear user ")
			if [[ -z "${match_clear}" ]]; then
				echo -e "${Error} 用户已使用流量清零失败 ${Green_font_prefix}[端口: ${Clear_transfer_user_port}]${Font_color_suffix} "
			else
				echo -e "${Info} 用户已使用流量清零成功 ${Green_font_prefix}[端口: ${Clear_transfer_user_port}]${Font_color_suffix} "
			fi
			break
		else
			echo -e "${Error} 请输入正确的端口 !"
		fi
	done
}
Clear_transfer_all(){
	cd "${ssr_folder}"
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} 没有发现 用户，请检查 !" && exit 1
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		match_clear=$(python mujson_mgr.py -c -p "${user_port}"|grep -w "clear user ")
		if [[ -z "${match_clear}" ]]; then
			echo -e "${Error} 用户已使用流量清零失败 ${Green_font_prefix}[端口: ${user_port}]${Font_color_suffix} "
		else
			echo -e "${Info} 用户已使用流量清零成功 ${Green_font_prefix}[端口: ${user_port}]${Font_color_suffix} "
		fi
	done
	echo -e "${Info} 所有用户流量清零完毕 !"
}
Clear_transfer_all_cron_start(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh/d" "$file/crontab.bak"
	echo -e "\n${Crontab_time} /bin/bash $file/ssrmu.sh clearall" >> "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh")
	if [[ -z ${cron_config} ]]; then
		echo -e "${Error} 定时所有用户流量清零启动失败 !" && exit 1
	else
		echo -e "${Info} 定时所有用户流量清零启动成功 !"
	fi
}
Clear_transfer_all_cron_stop(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh/d" "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh")
	if [[ ! -z ${cron_config} ]]; then
		echo -e "${Error} 定时所有用户流量清零停止失败 !" && exit 1
	else
		echo -e "${Info} 定时所有用户流量清零停止成功 !"
	fi
}
Clear_transfer_all_cron_modify(){
	Set_crontab
	Clear_transfer_all_cron_stop
	Clear_transfer_all_cron_start
}
Set_crontab(){
		echo -e "请输入流量清零时间间隔
 === 格式说明 ===
 * * * * * 分别对应 分钟 小时 日份 月份 星期
 ${Green_font_prefix} 0 2 1 * * ${Font_color_suffix} 代表 每月1日2点0分 清零已使用流量
 ${Green_font_prefix} 0 2 15 * * ${Font_color_suffix} 代表 每月15日2点0分 清零已使用流量
 ${Green_font_prefix} 0 2 */7 * * ${Font_color_suffix} 代表 每7天2点0分 清零已使用流量
 ${Green_font_prefix} 0 2 * * 0 ${Font_color_suffix} 代表 每个星期日(7) 清零已使用流量
 ${Green_font_prefix} 0 2 * * 3 ${Font_color_suffix} 代表 每个星期三(3) 清零已使用流量" && echo
	read -e -p "(默认: 0 2 1 * * 每月1日2点0分):" Crontab_time
	[[ -z "${Crontab_time}" ]] && Crontab_time="0 2 1 * *"
}
Start_SSR(){
	SSR_installation_status
	check_pid
	[[ ! -z ${PID} ]] && echo -e "${Error} ShadowsocksR 正在运行 !" && exit 1
	/etc/init.d/ssrmu start
}
Stop_SSR(){
	SSR_installation_status
	check_pid
	[[ -z ${PID} ]] && echo -e "${Error} ShadowsocksR 未运行 !" && exit 1
	/etc/init.d/ssrmu stop
}
Restart_SSR(){
	SSR_installation_status
	check_pid
	[[ ! -z ${PID} ]] && /etc/init.d/ssrmu stop
	/etc/init.d/ssrmu start
}
View_Log(){
	SSR_installation_status
	[[ ! -e ${ssr_log_file} ]] && echo -e "${Error} ShadowsocksR日志文件不存在 !" && exit 1
	echo && echo -e "${Tip} 按 ${Red_font_prefix}Ctrl+C${Font_color_suffix} Stop viewing logs" && echo -e "If you need to view the complete log content, please use ${Red_font_prefix}cat ${ssr_log_file}${Font_color_suffix} command。" && echo
	tail -f ${ssr_log_file}
}
# server speed
Configure_Server_Speeder(){
	echo && echo -e "what are you going to do？
 ${Green_font_prefix}1.${Font_color_suffix} Installation server speed
 ${Green_font_prefix}2.${Font_color_suffix} Uninstall server speed
————————
 ${Green_font_prefix}3.${Font_color_suffix} Start server speed
 ${Green_font_prefix}4.${Font_color_suffix} Stop server speed
 ${Green_font_prefix}5.${Font_color_suffix} Restart server speed
 ${Green_font_prefix}6.${Font_color_suffix} View server speed status
 
 Note: Ruisu and LotServer cannot be installed/started at the same time！" && echo
	read -e -p "(Default: cancel):" server_speeder_num
	[[ -z "${server_speeder_num}" ]] && echo "Cancelled..." && exit 1
	if [[ ${server_speeder_num} == "1" ]]; then
		Install_ServerSpeeder
	elif [[ ${server_speeder_num} == "2" ]]; then
		Server_Speeder_installation_status
		Uninstall_ServerSpeeder
	elif [[ ${server_speeder_num} == "3" ]]; then
		Server_Speeder_installation_status
		${Server_Speeder_file} start
		${Server_Speeder_file} status
	elif [[ ${server_speeder_num} == "4" ]]; then
		Server_Speeder_installation_status
		${Server_Speeder_file} stop
	elif [[ ${server_speeder_num} == "5" ]]; then
		Server_Speeder_installation_status
		${Server_Speeder_file} restart
		${Server_Speeder_file} status
	elif [[ ${server_speeder_num} == "6" ]]; then
		Server_Speeder_installation_status
		${Server_Speeder_file} status
	else
		echo -e "${Error} Please enter the correct number(1-6)" && exit 1
	fi
}
Install_ServerSpeeder(){
	[[ -e ${Server_Speeder_file} ]] && echo -e "${Error} Server Speeder Installed !" && exit 1
	#borrow 91yun.rog Rui Speed
	wget --no-check-certificate -qO /tmp/serverspeeder.sh https://raw.githubusercontent.com/91yun/serverspeeder/master/serverspeeder.sh
	[[ ! -e "/tmp/serverspeeder.sh" ]] && echo -e "${Error} Ruisu installation script download failed !" && exit 1
	bash /tmp/serverspeeder.sh
	sleep 2s
	PID=`ps -ef |grep -v grep |grep "serverspeeder" |awk '{print $2}'`
	if [[ ! -z ${PID} ]]; then
		rm -rf /tmp/serverspeeder.sh
		rm -rf /tmp/91yunserverspeeder
		rm -rf /tmp/91yunserverspeeder.tar.gz
		echo -e "${Info} Server Speeder The installation is complete !" && exit 1
	else
		echo -e "${Error} Server Speeder installation failed !" && exit 1
	fi
}
Uninstall_ServerSpeeder(){
	echo "Are you sure you want to uninstall Rui Su (Server Speeder)？[y/N]" && echo
	read -e -p "(default: n):" unyn
	[[ -z ${unyn} ]] && echo && echo "Cancelled..." && exit 1
	if [[ ${unyn} == [Yy] ]]; then
		chattr -i /serverspeeder/etc/apx*
		/serverspeeder/bin/serverSpeeder.sh uninstall -f
		echo && echo "Server Speeder Uninstall complete !" && echo
	fi
}
# LotServer
Configure_LotServer(){
	echo && echo -e "what are you going to do？
 ${Green_font_prefix}1.${Font_color_suffix} installation LotServer
 ${Green_font_prefix}2.${Font_color_suffix} Uninstall LotServer
————————
 ${Green_font_prefix}3.${Font_color_suffix} start  LotServer
 ${Green_font_prefix}4.${Font_color_suffix} stop LotServer
 ${Green_font_prefix}5.${Font_color_suffix} Reboot LotServer
 ${Green_font_prefix}6.${Font_color_suffix} View LotServer status
 
 Note: Ruisu and LotServer cannot be installed/started at the same time！" && echo
	read -e -p "(Default: cancel):" lotserver_num
	[[ -z "${lotserver_num}" ]] && echo "Cancelled..." && exit 1
	if [[ ${lotserver_num} == "1" ]]; then
		Install_LotServer
	elif [[ ${lotserver_num} == "2" ]]; then
		LotServer_installation_status
		Uninstall_LotServer
	elif [[ ${lotserver_num} == "3" ]]; then
		LotServer_installation_status
		${LotServer_file} start
		${LotServer_file} status
	elif [[ ${lotserver_num} == "4" ]]; then
		LotServer_installation_status
		${LotServer_file} stop
	elif [[ ${lotserver_num} == "5" ]]; then
		LotServer_installation_status
		${LotServer_file} restart
		${LotServer_file} status
	elif [[ ${lotserver_num} == "6" ]]; then
		LotServer_installation_status
		${LotServer_file} status
	else
		echo -e "${Error} Please enter the correct number(1-6)" && exit 1
	fi
}
Install_LotServer(){
	[[ -e ${LotServer_file} ]] && echo -e "${Error} LotServer Installed !" && exit 1
	#Github: https://github.com/0oVicero0/serverSpeeder_Install
	wget --no-check-certificate -qO /tmp/appex.sh "https://raw.githubusercontent.com/0oVicero0/serverSpeeder_Install/master/appex.sh"
	[[ ! -e "/tmp/appex.sh" ]] && echo -e "${Error} LotServer Installation script download failed !" && exit 1
	bash /tmp/appex.sh 'install'
	sleep 2s
	PID=`ps -ef |grep -v grep |grep "appex" |awk '{print $2}'`
	if [[ ! -z ${PID} ]]; then
		echo -e "${Info} LotServer The installation is complete !" && exit 1
	else
		echo -e "${Error} LotServer installation failed !" && exit 1
	fi
}
Uninstall_LotServer(){
	echo "Sure to uninstall LotServer？[y/N]" && echo
	read -e -p "(default: n):" unyn
	[[ -z ${unyn} ]] && echo && echo "Cancelled..." && exit 1
	if [[ ${unyn} == [Yy] ]]; then
		wget --no-check-certificate -qO /tmp/appex.sh "https://raw.githubusercontent.com/0oVicero0/serverSpeeder_Install/master/appex.sh" && bash /tmp/appex.sh 'uninstall'
		echo && echo "LotServer Uninstall complete !" && echo
	fi
}
# BBR
Configure_BBR(){
	echo && echo -e "  what are you going to do？
	
 ${Green_font_prefix}1.${Font_color_suffix} installation BBR
————————
 ${Green_font_prefix}2.${Font_color_suffix} start up BBR
 ${Green_font_prefix}3.${Font_color_suffix} stop BBR
 ${Green_font_prefix}4.${Font_color_suffix} View BBR status" && echo
echo -e "${Green_font_prefix} [Please note before installation] ${Font_color_suffix}
1. Install and turn on BBR, you need to replace the kernel, there are risks such as replacement failure (cannot boot after restart)
2. This script only supports kernel replacement for Debian / Ubuntu systems, OpenVZ and Docker do not support kernel replacement
3. During the process of kernel replacement, Debian will prompt [Whether to terminate unloading kernel]，please choose ${Green_font_prefix} NO ${Font_color_suffix}" && echo
	read -e -p "(Default: cancel):" bbr_num
	[[ -z "${bbr_num}" ]] && echo "Cancelled..." && exit 1
	if [[ ${bbr_num} == "1" ]]; then
		Install_BBR
	elif [[ ${bbr_num} == "2" ]]; then
		Start_BBR
	elif [[ ${bbr_num} == "3" ]]; then
		Stop_BBR
	elif [[ ${bbr_num} == "4" ]]; then
		Status_BBR
	else
		echo -e "${Error} Please enter the correct number(1-4)" && exit 1
	fi
}
Install_BBR(){
	[[ ${release} = "centos" ]] && echo -e "${Error}  CentOS BBR !" && exit 1
	BBR_installation_status
	bash "${BBR_file}"
}
Start_BBR(){
	BBR_installation_status
	bash "${BBR_file}" start
}
Stop_BBR(){
	BBR_installation_status
	bash "${BBR_file}" stop
}
Status_BBR(){
	BBR_installation_status
	bash "${BBR_file}" status
}
# Other functions
Other_functions(){
	echo && echo -e "  what are you going to do？
	
  ${Green_font_prefix}1.${Font_color_suffix} Configure BBR
  ${Green_font_prefix}2.${Font_color_suffix} Configuration ServerSpeeder
  ${Green_font_prefix}3.${Font_color_suffix} Configure LotServer (Ripspeed parent company)
  ${Tip} Ruisu/LotServer/BBR does not support OpenVZ！
  ${Tip} Sharp Speed ​​and LotServer cannot coexist！
————————————
  ${Green_font_prefix}4.${Font_color_suffix} 一Key block BT/PT/SPAM (iptables)
  ${Green_font_prefix}5.${Font_color_suffix} 一Key unblock BT/PT/SPAM (iptables)
————————————
  ${Green_font_prefix}6.${Font_color_suffix} Switch ShadowsocksR log output mode
  —— Note: SSR only outputs error logs by default, this item can be switched to output detailed access logs。
  ${Green_font_prefix}7.${Font_color_suffix} Monitor the running status of the ShadowsocksR server
  —— note：This function is suitable for the end of the process of the SSR server frequently. After starting this function, it will be detected every minute. When the process does not exist, the SSR server will be automatically started。" && echo
	read -e -p "(Default: cancel):" other_num
	[[ -z "${other_num}" ]] && echo "Cancelled..." && exit 1
	if [[ ${other_num} == "1" ]]; then
		Configure_BBR
	elif [[ ${other_num} == "2" ]]; then
		Configure_Server_Speeder
	elif [[ ${other_num} == "3" ]]; then
		Configure_LotServer
	elif [[ ${other_num} == "4" ]]; then
		BanBTPTSPAM
	elif [[ ${other_num} == "5" ]]; then
		UnBanBTPTSPAM
	elif [[ ${other_num} == "6" ]]; then
		Set_config_connect_verbose_info
	elif [[ ${other_num} == "7" ]]; then
		Set_crontab_monitor_ssr
	else
		echo -e "${Error} Please enter the correct number [1-7]" && exit 1
	fi
}
# block BT PT SPAM
BanBTPTSPAM(){
	wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/ban_iptables.sh && chmod +x ban_iptables.sh && bash ban_iptables.sh banall
	rm -rf ban_iptables.sh
}
# Unblock BT PT SPAM
UnBanBTPTSPAM(){
	wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/ban_iptables.sh && chmod +x ban_iptables.sh && bash ban_iptables.sh unbanall
	rm -rf ban_iptables.sh
}
Set_config_connect_verbose_info(){
	SSR_installation_status
	[[ ! -e ${jq_file} ]] && echo -e "${Error} JQThe parser does not exist, please check !" && exit 1
	connect_verbose_info=`${jq_file} '.connect_verbose_info' ${config_user_file}`
	if [[ ${connect_verbose_info} = "0" ]]; then
		echo && echo -e "Current log mode: ${Green_font_prefix}Simple mode (only output error log）${Font_color_suffix}" && echo
		echo -e "Sure you want to switch to ${Green_font_prefix}Verbose mode (output detailed connection log + error log）${Font_color_suffix}？[y/N]"
		read -e -p "(default: n):" connect_verbose_info_ny
		[[ -z "${connect_verbose_info_ny}" ]] && connect_verbose_info_ny="n"
		if [[ ${connect_verbose_info_ny} == [Yy] ]]; then
			ssr_connect_verbose_info="1"
			Modify_config_connect_verbose_info
			Restart_SSR
		else
			echo && echo "	Cancelled..." && echo
		fi
	else
		echo && echo -e "Current log mode: ${Green_font_prefix}Verbose mode (output detailed connection log + error log）${Font_color_suffix}" && echo
		echo -e "Sure you want to switch to ${Green_font_prefix}Simple mode（Only output error log）${Font_color_suffix}？[y/N]"
		read -e -p "(default: n):" connect_verbose_info_ny
		[[ -z "${connect_verbose_info_ny}" ]] && connect_verbose_info_ny="n"
		if [[ ${connect_verbose_info_ny} == [Yy] ]]; then
			ssr_connect_verbose_info="0"
			Modify_config_connect_verbose_info
			Restart_SSR
		else
			echo && echo "	Cancelled..." && echo
		fi
	fi
}
Set_crontab_monitor_ssr(){
	SSR_installation_status
	crontab_monitor_ssr_status=$(crontab -l|grep "ssrmu.sh monitor")
	if [[ -z "${crontab_monitor_ssr_status}" ]]; then
		echo && echo -e "Current monitoring mode: ${Green_font_prefix}Unopened${Font_color_suffix}" && echo
		echo -e "Sure to open as ${Green_font_prefix}ShadowsocksR Server running status monitoring${Font_color_suffix} Function？(Automatically start the SSR server when the process is closed)[Y/n]"
		read -e -p "(default: y):" crontab_monitor_ssr_status_ny
		[[ -z "${crontab_monitor_ssr_status_ny}" ]] && crontab_monitor_ssr_status_ny="y"
		if [[ ${crontab_monitor_ssr_status_ny} == [Yy] ]]; then
			crontab_monitor_ssr_cron_start
		else
			echo && echo "	Cancelled..." && echo
		fi
	else
		echo && echo -e "Current monitoring mode: ${Green_font_prefix}Turned on${Font_color_suffix}" && echo
		echo -e "Sure to close as ${Green_font_prefix}ShadowsocksR Server running status monitoring${Font_color_suffix} Function？(Automatically start the SSR server when the process is closed)[y/N]"
		read -e -p "(default: n):" crontab_monitor_ssr_status_ny
		[[ -z "${crontab_monitor_ssr_status_ny}" ]] && crontab_monitor_ssr_status_ny="n"
		if [[ ${crontab_monitor_ssr_status_ny} == [Yy] ]]; then
			crontab_monitor_ssr_cron_stop
		else
			echo && echo "	Cancelled..." && echo
		fi
	fi
}
crontab_monitor_ssr(){
	SSR_installation_status
	check_pid
	if [[ -z ${PID} ]]; then
		echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] detected ShadowsocksR The server is not running, start to start..." | tee -a ${ssr_log_file}
		/etc/init.d/ssrmu start
		sleep 1s
		check_pid
		if [[ -z ${PID} ]]; then
			echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] ShadowsocksR Server start failed..." | tee -a ${ssr_log_file} && exit 1
		else
			echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] ShadowsocksR Server started successfully..." | tee -a ${ssr_log_file} && exit 1
		fi
	else
		echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] ShadowsocksR The server process is running normally..." exit 0
	fi
}
crontab_monitor_ssr_cron_start(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh monitor/d" "$file/crontab.bak"
	echo -e "\n* * * * * /bin/bash $file/ssrmu.sh monitor" >> "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh monitor")
	if [[ -z ${cron_config} ]]; then
		echo -e "${Error} ShadowsocksR Server running status monitoring function failed to start !" && exit 1
	else
		echo -e "${Info} ShadowsocksR Server running status monitoring function started successfully !"
	fi
}
crontab_monitor_ssr_cron_stop(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh monitor/d" "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh monitor")
	if [[ ! -z ${cron_config} ]]; then
		echo -e "${Error} ShadowsocksR Server running status monitoring function Stop failure !" && exit 1
	else
		echo -e "${Info} ShadowsocksR Server running status monitoring function stopped successfully !"
	fi
}
Update_Shell(){
	sh_new_ver=$(wget --no-check-certificate -qO- -t1 -T3 "https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/ssrmu.sh"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1) && sh_new_type="github"
	[[ -z ${sh_new_ver} ]] && echo -e "${Error} Cannot link to Github !" && exit 0
	if [[ -e "/etc/init.d/ssrmu" ]]; then
		rm -rf /etc/init.d/ssrmu
		Service_SSR
	fi
	cd "${file}"
	wget -N --no-check-certificate "https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/ssrmu.sh" && chmod +x ssrmu.sh
	echo -e "The script has been updated to the latest version[ ${sh_new_ver} ] !(Note: Because the update method is to directly overwrite the currently running script, some errors may be prompted below, just ignore it)" && exit 0
}
# Display menu status
menu_status(){
	if [[ -e ${ssr_folder} ]]; then
		check_pid
		if [[ ! -z "${PID}" ]]; then
			echo -e " Current state: ${Green_font_prefix}Installed${Font_color_suffix} 并 ${Green_font_prefix}have not started${Font_color_suffix}"
		else
			echo -e " Current state: ${Green_font_prefix}Installed${Font_color_suffix} 但 ${Red_font_prefix}have not started${Font_color_suffix}"
		fi
		cd "${ssr_folder}"
	else
		echo -e " Current state: ${Red_font_prefix}Not Installed${Font_color_suffix}"
	fi
}
check_sys
[[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && [[ ${release} != "centos" ]] && echo -e "${Error} This script does not support the current system ${release} !" && exit 1
action=$1
if [[ "${action}" == "clearall" ]]; then
	Clear_transfer_all
elif [[ "${action}" == "monitor" ]]; then
	crontab_monitor_ssr
else
	echo -e "  ShadowsocksR MuJSON One-click management script ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
  ---- Toyo | doub.io/ss-jc60 ----

  ${Green_font_prefix}1.${Font_color_suffix} Install SSR
  ${Green_font_prefix}2.${Font_color_suffix} Update SSR
  ${Green_font_prefix}3.${Font_color_suffix} Uninstall SSR
  ${Green_font_prefix}4.${Font_color_suffix} Install Libsodium(chacha20)
————————————
  ${Green_font_prefix}5.${Font_color_suffix} View User
  ${Green_font_prefix}6.${Font_color_suffix} View user connection info
  ${Green_font_prefix}7.${Font_color_suffix} Modify Config user
  ${Green_font_prefix}8.${Font_color_suffix} Manually Modify Config
  ${Green_font_prefix}9.${Font_color_suffix} Clear transfer
————————————
 ${Green_font_prefix}10.${Font_color_suffix} start up ShadowsocksR
 ${Green_font_prefix}11.${Font_color_suffix} stop ShadowsocksR
 ${Green_font_prefix}12.${Font_color_suffix} Reboot ShadowsocksR
 ${Green_font_prefix}13.${Font_color_suffix} View ShadowsocksR Log
————————————
 ${Green_font_prefix}14.${Font_color_suffix} Other functions
 ${Green_font_prefix}15.${Font_color_suffix} Upgrade script
 "
	menu_status
	echo && read -e -p "Please key in numbers [1-15]：" num
case "$num" in
	1)
	Install_SSR
	;;
	2)
	Update_SSR
	;;
	3)
	Uninstall_SSR
	;;
	4)
	Install_Libsodium
	;;
	5)
	View_User
	;;
	6)
	View_user_connection_info
	;;
	7)
	Modify_Config
	;;
	8)
	Manually_Modify_Config
	;;
	9)
	Clear_transfer
	;;
	10)
	Start_SSR
	;;
	11)
	Stop_SSR
	;;
	12)
	Restart_SSR
	;;
	13)
	View_Log
	;;
	14)
	Other_functions
	;;
	15)
	Update_Shell
	;;
	*)
	echo -e "${Error} Please enter the correct number [1-15]"
	;;
esac
fi
