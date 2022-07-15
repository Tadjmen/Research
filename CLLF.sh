#!/usr/bin/env bash
# coded by XuanMike
# C - version 1.0
# CLLF - Collect Linux Logs Forensic


#@> VARIABLES
OUTDIR=CLLF_$(date +%F_%H-%M-%S)
mkdir $OUTDIR
cd $OUTDIR
touch errors.txt
VR=" v1.0"


#@> COLORS
BK="\e[7m"
RT="\e[0m"
YW="\e[93m"
GR="\e[32m"



#@> EXIT FUNCTION
trap ctrl_c INT
ctrl_c(){
    echo -e ""
    echo -e "${YW} [!] ${RT} KEYBOARD INTERRUPTION, ${GR}EXITING CLLF${RT}..."
    exit 127
}

#@> Print BANNER
BANNER(){
    clear
    echo -e ""
    echo -e "${YW}
\t\t ██████╗██╗     ██╗     ███████╗
\t\t██╔════╝██║     ██║     ██╔════╝
\t\t██║     ██║     ██║     █████╗  
\t\t██║     ██║     ██║     ██╔══╝  
\t\t╚██████╗███████╗███████╗██║     
\t\t ╚═════╝╚══════╝╚══════╝╚═╝     
\t\t   
${RT}"
    echo -e "[${YW}CLLF${RT}] == A Collecter Collect Linux Logs Forensic by (${BK}@XuanMike${RT})"

}


#@> GET ENV
GET_ENV(){
    #
    # @desc   :: This function saves all installed environment variable and functions
    #
	echo -e "${BK}        ${RT}" | tr -d '\n' |  echo -e " Processing environment variables... ${BK}${RT} (${YW}it may take time${RT})"
	mkdir environment_vars && cd environment_vars
	touch errors.txt
	printenv > "printenv.txt" 2>>errors.txt
	set > "set.txt" 2>>errors.txt
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " COLLECTED: environment variables ${BK}${RT} (${YW}OK${RT})"
	cd ..
}

#@> GET MODULES
GET_MODULES(){
    #
    # @desc   :: This function saves loaded modules
    #
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " Processing modules... ${BK}${RT} (${YW}it may take time${RT})"
	mkdir modules && cd modules
	touch errors.txt
	lsmod > "lsmod.txt" 2>>errors.txt
	cat /proc/modules > "proc_modules.txt" 2>>errors.txt
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " COLLECTED: Modules are successfully saved. ${BK}${RT} (${YW}OK${RT})"
	cd ..
}


#@> GET SYS
GET_SYS(){
    #
    # @desc   :: This function saves system
    #
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " Processing system... ${BK}${RT} (${YW}it may take time${RT})"
	mkdir system && cd system
	touch errors.txt
	cat /proc/version > "proc_version.txt" 2>>errors.txt
	uname -a > "uname.txt" 2>>errors.txt
	hostname > "hostname.txt" 2>>errors.txt
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " COLLECTED: System are successfully saved. ${BK}${RT} (${YW}OK${RT})"
	cd ..
}


#@> GET DISK
GET_DISK(){
    #
    # @desc   :: This function saves disks state
    #
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " Processing disks ... ${BK}${RT} (${YW}it may take time${RT})"
	mkdir disks && cd disks
	touch errors.txt
	fdisk -l > "fdisk.txt" 2>>errors.txt
	df -h > "df_h.txt" 2>>errors.txt
	findmnt -a -A > "findmnt.txt" 2>>errors.txt
	vgdisplay -v > "vgdisplay.txt" 2>>errors.txt
	lvdisplay -v > "lvdisplay.txt" 2>>errors.txt
	vgs --all > "vgs.txt" 2>>errors.txt
	lvs --all > "lvs.txt" 2>>errors.txt
	free > "free.txt" 2>>errors.txt
	cat /proc/partitions > "proc_partitions.txt" 2>>errors.txt
	du -sh > "du.txt" 2>>errors.txt
	cat /etc/fstab > "fstab.txt" 2>>errors.txt
	cat /etc/mtab > "mtab.txt" 2>>errors.txt
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " COLLECTED: Disks  are successfully saved. ${BK}${RT} (${YW}OK${RT})"
	cd ..
}


#@> GET PACKAGES
GET_PACKAGES(){
    #
    # @desc   :: This function saves all installed packages
    #
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " Processing packages ... ${BK}${RT} (${YW}it may take time${RT})"
	mkdir packages && cd packages
	touch errors.txt
	apt list --installed > "apt_list_installed.txt" 2>>errors.txt
	dpkg -l > "dpkg_l.txt" 2>>errors.txt
	dpkg -V > "dpkg_V.txt" 2>>errors.txt
	dpkg-query -l > "dpkg_query.txt" 2>>errors.txt
	yum list installed > "yum_list_installed.txt" 2>>errors.txt
	dnf list installed > "dnf_list_installed.txt" 2>>errors.txt
	rpm -qa > "rpm_qa.txt" 2>>errors.txt
	rpm -Va > "rpm_Va.txt" 2>>errors.txt
	snap list > "snap_list.txt" 2>>errors.txt
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " COLLECTED: Packages  are successfully saved. ${BK}${RT} (${YW}OK${RT})"
	cd ..
}


#@> GET ACCOUNT
GET_ACCOUNT(){
    #
    # @desc   :: This function saves users and groups
    #
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " Processing users and groups ... ${BK}${RT} (${YW}it may take time${RT})"
	mkdir accounts && cd accounts
	touch errors.txt
	cat /etc/passwd > "etc_passwd.txt" 2>>errors.txt
	cat /etc/passwd- > "etc_passwd-.txt" 2>>errors.txt
	cat /etc/group > "etc_group.txt" 2>>errors.txt
	cat /etc/group- > "etc_group-.txt" 2>>errors.txt
	cat /etc/shadow > "etc_shadow.txt" 2>>errors.txt
	cat /etc/shadow- > "etc_shadow-.txt" 2>>errors.txt
	cat /etc/gshadow > "etc_gshadow.txt" 2>>errors.txt
	cat /etc/gshadow- > "etc_gshadow-.txt" 2>>errors.txt
	who -alpu > "who_alpu.txt" 2>>errors.txt
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " COLLECTED: Accounts are successfully saved. ${BK}${RT} (${YW}OK${RT})"
	cd ..
}


#@> GET PROCESS
GET_PROCESS(){
    #
    # @desc   :: This function saves running process
    #
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " Processing process ... ${BK}${RT} (${YW}it may take time${RT})"
	mkdir process && cd process
	touch errors.txt
	pstree > "pstree.txt" 2>>errors.txt
	ps faux > "ps_faux.txt" 2>>errors.txt
	top -H -b -n 1 > "top.txt" 2>>errors.txt
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " COLLECTED: Process are successfully saved. ${BK}${RT} (${YW}OK${RT})"
	cd ..
}


#@> GET SERVICES
GET_SERVICES(){
    #
    # @desc   :: This function saves services
    #
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " Processing services ... ${BK}${RT} (${YW}it may take time${RT})"
	mkdir services && cd services
	touch errors.txt
	systemctl list-units --all > "systemctl_list_units.txt" 2>>errors.txt
	(ls -la /etc/systemd/system/**/*.service /usr/lib/systemd/**/*.service) > "ls_systemd_system.txt" 2>>errors.txt
	service --status-all > "service_status_all.txt" 2>>errors.txt
	firewall-cmd --list-services > "firewall_cmd.txt" 2>>errors.txt
	chkconfig --list > "chkconfig.txt" 2>>errors.txt
	systemctl --type=service --state=failed > "systemctl_services_failed.txt" 2>>errors.txt
	systemctl --type=service --state=active > "systemctl_services_active.txt" 2>>errors.txt
	systemctl --type=service --state=running > "systemctl_services_running.txt" 2>>errors.txt
	ls -l /etc/init.d/* > "ls_etc_initd.txt" 2>>errors.txt
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " COLLECTED: services are successfully saved. ${BK}${RT} (${YW}OK${RT})"
	cd ..
}


#@> GET OPENED PORTS
GET_OPENED_PORTS(){
    #
    # @desc   :: This function saves opened ports
    #
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " Processing ports ... ${BK}${RT} (${YW}it may take time${RT})"
	mkdir ports && cd ports
	touch errors.txt
	ss --all > "ss_all.txt" 2>>errors.txt
	ss -lntu > "ss_lntu.txt" 2>>errors.txt
	netstat -a > "netstat_a" 2>>errors.txt
	netstat -lntu > "netstat_lntu" 2>>errors.txt
	lsof -i -n -P > "lsof.txt" 2>>errors.txt
	firewall-cmd --list-ports > "firewall_cmd_list_ports.txt" 2>>errors.txt
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " COLLECTED: ports are successfully saved. ${BK}${RT} (${YW}OK${RT})"
	cd ..
}


#@> GET ARP CACHE
GET_ARP_CACHE(){
    #
    # @desc   :: This function saves arp cache
    #
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " Processing arp cache ... ${BK}${RT} (${YW}it may take time${RT})"
	mkdir arp_cache && cd arp_cache
	touch errors.txt
	arp -a > "arp_a.txt" 2>>errors.txt
	cat /proc/net/arp > "proc_net_arp.txt" 2>>errors.txt
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " COLLECTED: arp cache are successfully saved. ${BK}${RT} (${YW}OK${RT})"
	cd ..
}


#@> GET NETWORK TRAFFIC
GET_NETWORK_TRAFFIC(){
    #
    # @desc   :: This function saves network traffic statistics
    #
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " Processing traffic ... ${BK}${RT} (${YW}it may take time${RT})"
	mkdir traffic && cd traffic
	touch errors.txt
	(grep -H . /sys/class/net/*/statistics/rx_packets) > "rx_packets.txt" 2>>errors.txt
	ip -s -s link > "all_rx_tx_packets.txt" 2>>errors.txt
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " COLLECTED: traffic are successfully saved. ${BK}${RT} (${YW}OK${RT})"
	cd ..
}


#@> GET NETWORK INTERFACES
GET_NETWORK_INTERFACES(){
    #
    # @desc   :: This function saves network interfaces
    #
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " Processing interfaces ... ${BK}${RT} (${YW}it may take time${RT})"
	mkdir interfaces && cd interfaces
	touch errors.txt
	ifconfig -a > "ifconfig_a.txt" 2>>errors.txt
	iwconfig > "iwconfig.txt" 2>>errors.txt
	ip addr > "ip_addr.txt" 2>>errors.txt
	cat /proc/net/dev > "proc_net_dev.txt" 2>>errors.txt
	netstat -i > "netstat_i.txt" 2>>errors.txt
	nmcli device status > "nmcli_device_status.txt" 2>>errors.txt
	lshw -class network -short > "lshw.txt" 2>>errors.txt
	hwinfo --short --network > "hwinfo.txt" 2>>errors.txt
	cat /etc/hosts > "etc_hosts.txt" 2>>errors.txt
	cat /etc/hosts.allow > "etc_hosts_allow.txt" 2>>errors.txt
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " COLLECTED: interfaces are successfully saved. ${BK}${RT} (${YW}OK${RT})"
	cd ..
}


#@> GET TASKS
GET_TASKS(){
    #
    # @desc   :: This function saves scheduled tasks (servicse, cron, rc, .profile ...)
    #
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " Processing tasks ... ${BK}${RT} (${YW}it may take time${RT})"
	mkdir tasks && cd tasks
	touch errors.txt
	(cat /etc/*bashrc* /home/*/.bashrc* /home/*/.bash_profile* /home/*/.profile* /home/*/.bash_login /root/.bashrc* /home/*/.profile* /root/.profile* /root/.bash_login) > "bashrc.txt" 2>>errors.txt
	(cat /etc/*cron**/* /etc/cron* /var/spool/**/cron*) > "cron.txt" 2>>errors.txt
	(cat /etc/systemd/system/**/*.service /usr/lib/systemd/**/*.service) > "systemd.txt" 2>>errors.txt
	(cat /etc/rc*.d**/* /etc/rc.local*) > "rc.txt" 2>>errors.txt
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " COLLECTED: tasks are successfully saved. ${BK}${RT} (${YW}OK${RT})"
	cd ..
}


#@> GET LOGS
GET_LOGS(){
    #
    # @desc   :: This function saves logs
    #
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " Processing logs ... ${BK}${RT} (${YW}it may take time${RT})"
	mkdir logs && cd logs
	touch errors.txt
	last -Faixw > "last.txt" 2>>errors.txt
	journalctl -x > "journalctl_x.txt" 2>>errors.txt
	journalctl -k > "journalctl_k.txt" 2>>errors.txt
	cat /var/log/apache*/**access* > "apache_access.txt" 2>>errors.txt
	cat /var/log/apache*/**error* > "apache_error.txt" 2>>errors.txt
	cat /var/log/boot** > "boot.txt" 2>>errors.txt
	cat /var/log/btmp** > "btmp.txt" 2>>errors.txt
	cat /var/log/wtmp** > "wtmp.txt" 2>>errors.txt
	cat /var/log/httpd/**access* > "httpd_access.txt" 2>>errors.txt
	cat /var/log/httpd/**error* > "httpd_error.txt" 2>>errors.txt
	cat /var/log/kern** > "kern.txt" 2>>errors.txt
	cat /var/log/mail** > "mail.txt" 2>>errors.txt
	cat /var/log/mariadb/** > "mariadb.txt" 2>>errors.txt
	cat /var/log/message** > "message.txt" 2>>errors.txt
	cat /var/log/mysql/** > "mysql.txt" 2>>errors.txt
	cat /var/log/nginx/**access* > "nginx_access.txt" 2>>errors.txt
	cat /var/log/nginx/**error* > "nginx_error.txt" 2>>errors.txt
	cat /var/log/secure** > "secure.txt" 2>>errors.txt
	cat /var/log/squid/**access* > "squid_proxy.txt" 2>>errors.txt
	cat /var/log/syslog** > "syslog.txt" 2>>errors.txt
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " COLLECTED: logs are successfully saved. ${BK}${RT} (${YW}OK${RT})"
	cd ..
}

#@> GET CONFIGURATIONS
GET_CONFIGURATIONS(){
    #
    # @desc   :: This function saves configurations
    #
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " Processing configurations ... ${BK}${RT} (${YW}it may take time${RT})"
	mkdir configurations && cd configurations
	touch errors.txt
	iptables -S > "bashrc.txt" 2>>errors.txt
	firewall-cmd --list-all > "firewall-cmd.txt" 2>>errors.txt
	sshd -T > "sshd_T.txt" 2>>errors.txt
	sysctl -a > "sysctl.txt" 2>>errors.txt
	cat /etc/apache*/*.conf> "apache_conf.txt" 2>>errors.txt
	cat /etc/apt**/*.list* > "apt_conf.txt" 2>>errors.txt
	cat /etc/firewalld/*.conf > "firewall_conf.txt" 2>>errors.txt
	cat /boot/grub/grub.conf* > "grub_conf.txt" 2>>errors.txt
	cat /etc/httpd/*.conf > "httpd_conf.txt" 2>>errors.txt
	cat /etc/ipsec* /etc/ipsec**/* > "ipsec_conf.txt" 2>>errors.txt
	cat /etc/mariadb/* > "mariadb_conf.txt" 2>>errors.txt
	cat /etc/modprobe.d/* /etc/modprobe.d/**/* > "modprobe_conf.txt" 2>>errors.txt
	cat /etc/mysql/* > "mysql_conf.txt" 2>>errors.txt
	cat /etc/nftables* > "nftables_conf.txt" 2>>errors.txt
	cat /etc/nginx/* > "nginx_conf.txt" 2>>errors.txt
	cat /etc/ntp* > "ntp_conf.txt" 2>>errors.txt
	cat /etc/pam* /etc/pam**/* > "pam_conf.txt" 2>>errors.txt
	cat /etc/postgresql*/* /etc/postgresql**/* > "postgresql_conf.txt" 2>>errors.txt
	cat /etc/resolv* > "resolv_conf.txt" 2>>errors.txt
	cat /etc/rsyslog* /etc/rsyslog**/* > "rsyslog_conf.txt" 2>>errors.txt
	cat /etc/samba**/* > "samba_conf.txt" 2>>errors.txt
	cat /etc/security**/* > "security_conf.txt" 2>>errors.txt
	cat /etc/selinux/* > "selinux_conf.txt" 2>>errors.txt
	cat /etc/snmp/* > "snmp_conf.txt" 2>>errors.txt
	cat /etc/ssh**/* > "ssh_conf.txt" 2>>errors.txt
	cat /etc/sudo* /etc/sudo**/* > "sudo_conf.txt" 2>>errors.txt
	cat /etc/sudoers* /etc/sudoers**/* > "sudoers_conf.txt" 2>>errors.txt
	cat /etc/sysctl* /etc/sysctl**/* > "sysctl_conf.txt" 2>>errors.txt
	cat /etc/yum.* /etc/yum**/* > "yum_conf.txt" 2>>errors.txt
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " COLLECTED: Configurations are successfully saved. ${BK}${RT} (${YW}OK${RT})"
	cd ..
}

#@> GET WEBSERVERSCRIPTS
GET_WEBSERVERSCRIPTS(){
    #
    # @desc   :: This function saves web server scripts
    #
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " Processing web server scripts... ${BK}${RT} (${YW}it may take time${RT})"
	mkdir WebServerScripts && cd WebServerScripts
	mkdir webscriptsFile
	touch errors.txt
	ls /var/www/**/*.py /var/www/**/*.php /var/www/**/*.js /var/www/**/*.rb /var/www/**/*.pl /var/www/**/*.cgi /var/www/**/*.sh /var/www/**/*.go /var/www/**/*.war 2>dev\null | grep ".*" > webscripts.txt 2>>errors.txt
	xargs -a webscripts.txt -P 50 -I % bash -c "cp % webscriptsFile" 2>>errors.txt
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " COLLECTED: web server scripts are successfully saved. ${BK}${RT} (${YW}OK${RT})"
	cd ..  
}

#@> GET HISTORIES
GET_HISTORIES(){
    #
    # @desc   :: This function saves histories
    #
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " Processing Histories... ${BK}${RT} (${YW}it may take time${RT})"
	mkdir histories && cd histories
	mkdir historiesFile
	touch errors.txt
	ls /home/*/\.*_history /root/\.*_history | grep ".*" > "histories.txt" 2>>errors.txt
	xargs -a histories.txt -P 50 -I % bash -c "cp % historiesFile > " 2>>errors.txt
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " COLLECTED: Histories are successfully saved. ${BK}${RT} (${YW}OK${RT})"
	cd ..  
}

#@> GET SUSPICIOUS
GET_SUSPICIOUS(){
    #
    # @desc   :: This function saves suspicious files
    #
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " Processing suspicious files... ${BK}${RT} (${YW}it may take time${RT})"
	mkdir suspicious && cd suspicious
	mkdir suspiciousFile
	touch errors.txt
	find /tmp -type f -perm /+x > "suspicious.txt" 2>>errors.txt
	xargs -a suspicious.txt -P 50 -I % bash -c "cp % suspiciousFile > " 2>>errors.txt
	echo -e "${BK}        ${RT}" | tr -d '\n' | echo -e " COLLECTED: suspicious files are successfully saved. ${BK}${RT} (${YW}OK${RT})"
	cd ..  
}



#@> SENDING FINAL NOTIFICATION
SEND_NOTE(){
    echo -e ""
    echo -e "${BK} SCANNING COMPLETED SUCCESSFULLY ON $DM ${RT}"
    echo -e "[CLLF] - Scanning completed on $DM at $(date)" | notify -silent
}

RUN(){
	GET_ENV
	GET_MODULES
	GET_SYS
	GET_DISK
	GET_PACKAGES
	GET_ACCOUNT
	GET_PROCESS
	GET_SERVICES
	GET_OPENED_PORTS
	GET_ARP_CACHE
	GET_NETWORK_TRAFFIC
	GET_NETWORK_INTERFACES
	GET_TASKS
	GET_LOGS
	GET_CONFIGURATIONS
	GET_WEBSERVERSCRIPTS
	GET_HISTORIES
	GET_SUSPICIOUS
}

#while true
#do
#    BANNER
#    RUN
#    exit 0
#done

BANNER
RUN
