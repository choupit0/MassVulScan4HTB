#!/bin/bash

##############################################################################################################################
# 
# Script Name    : MassVulScan4HTB.sh
# Description    : This script is a variant of the initial script (MassVulScan.sh). It is adapted to the HackTheBox Platform:
#                  Pwnbox: https://www.hackthebox.eu/home/pwnbox
#                  This script combines the high processing speed to find open ports (MassScan), the effectiveness
#                  to identify open services versions and find potential CVE vulnerabilities (Nmap + vulners.nse script).
#                  A beautiful report (nmap-bootstrap.xsl) is generated containing all the open ports found and services,
#                  and finally a text file including specifically the potential vulnerabilities is created.
# Author         : https://github.com/choupit0
# Site           : https://hack2know.how/
# HTB Profile    : https://www.hackthebox.eu/home/users/profile/144352
# Date           : 20200827
# Version        : 1.0.0
# Usage          : ./MassVulScan4HTB.sh [IPv4]]
# Prerequisites  : Install MassScan (>=1.0.5), Nmap and vulners.nse (nmap script) to use this script.
#                  Xsltproc package is also necessary.
#                  Please, read the file "requirements.txt" if you need some help.
#                  The installation of these prerequisites is automatic.
#
##############################################################################################################################

version="1.0.0"
yellow_color="\033[1;33m"
green_color="\033[0;32m"
red_color="\033[1;31m"
error_color="\033[1;41m"
blue_color="\033[0;36m"
bold_color="\033[1m"
end_color="\033[0m"
source_installation="./sources/installation.sh"
script_start="$SECONDS"
report_folder="$(pwd)/reports/"
host="$1"
interface="tun0"
rate="1000"
ports="-p1-65535,U:1-65535"
script="vulners"

# Time elapsed 
time_elapsed(){
script_end="$SECONDS"
script_duration="$((script_end-script_start))"

printf 'Duration: %02dh:%02dm:%02ds\n' $((${script_duration}/3600)) $((${script_duration}%3600/60)) $((${script_duration}%60))
}

# Root user?
root_user(){
if [[ $(id -u) != "0" ]]; then
	echo -e "${red_color}[X] You are not the root.${end_color}"
	echo "Assuming your are in the sudoers list, please launch the script with \"sudo\"."
	exit 1
fi
}

# Verifying if installation source file exist
source_file(){
if [[ -z ${source_installation} ]] || [[ ! -s ${source_installation} ]]; then
	echo -e "${red_color}[X] Source file \"${source_installation}\" does not exist or is empty.${end_color}"
	echo -e "${yellow_color}[I] This script can install the prerequisites for you.${end_color}"
	echo "Please, download the source from Github and try again: git clone https://github.com/choupit0/MassVulScan.git"
	exit 1
fi
}

# Checking prerequisites
if [[ ! $(which masscan) ]] || [[ ! $(which nmap) ]] || [[ ! $(locate vulners.nse) ]] || [[ ! $(which xsltproc) ]]; then
	echo -e "${red_color}[X] There are some prerequisites to install before to launch this script.${end_color}"
	echo -e "${yellow_color}[I] Please, read the help file \"requirements.txt\" for installation instructions (Debian/Ubuntu):${end_color}"
	echo "$(grep ^-- "requirements.txt")"
	# Automatic installation for Debian OS family
	source_file
	source "${source_installation}"
	else
		masscan_version="$(masscan -V | grep "Masscan version" | cut -d" " -f3)"
		nmap_version="$(nmap -V | grep "Nmap version" | cut -d" " -f3)"
		if [[ ${masscan_version} < "1.0.5" ]]; then
			echo -e "${red_color}[X] Masscan is not up to date.${end_color}"
			echo "Please. Be sure to have the last Masscan version >= 1.0.5."
			echo "Your current version is: ${masscan_version}"
			# Automatic installation for Debian OS family
			source_file
			source "${source_installation}"
		fi
		if [[ ${nmap_version} < "7.60" ]]; then
			echo -e "${red_color}[X] Nmap is not up to date.${end_color}"
			echo "Please. Be sure to have Nmap version >= 7.60."
			echo "Your current version is: ${nmap_version}"
			# Automatic installation for Debian OS family
			source_file
			source "${source_installation}"
		fi
fi


# Logo
logo(){
echo -e ""
echo -e "${red_color}@@@@@@@@@@   @@@  @@@   @@@@@@        @@@   @@@  @@@  @@@@@@@  @@@@@@@   "
echo -e "${red_color}@@@@@@@@@@@  @@@  @@@  @@@@@@@       @@@@   @@@  @@@  @@@@@@@  @@@@@@@@  "
echo -e "${red_color}@@! @@! @@!  @@!  @@@  !@@          @@!@!   @@!  @@@    @@!    @@!  @@@  "
echo -e "${red_color}!@! !@! !@!  !@!  @!@  !@!         !@!!@!   !@!  @!@    !@!    !@   @!@  "
echo -e "${red_color}@!! !!@ @!@  @!@  !@!  !!@@!!     @!! @!!   @!@!@!@!    @!!    @!@!@!@   "
echo -e "${red_color}!@!   ! !@!  !@!  !!!   !!@!!!   !!!  !@!   !!!@!!!!    !!!    !!!@!!!!  "
echo -e "${red_color}!!:     !!:  :!:  !!:       !:!  :!!:!:!!:  !!:  !!!    !!:    !!:  !!!  "
echo -e "${red_color}:!:     :!:   ::!!:!       !:!   !:::!!:::  :!:  !:!    :!:    :!:  !:!  "
echo -e "${red_color}:::     ::     ::::    :::: ::        :::   ::   :::     ::     :: ::::  "
echo -e "${red_color} :      :       :      :: : :         :::    :   : :     :     :: : ::   "
echo -e "${end_color}"
echo -e "${yellow_color}[I] Version ${version}"
}

# Usage of script
usage(){
        logo
	echo -e "${blue_color}${bold_color}[-] Usage: Root user or sudo${end_color} ./$(basename "$0") [IPv4]"
	echo -e "${yellow_color}${bold_color}[I] Bash script for the web-based Parrot Linux instance Pwnbox from HTB${end_color}"
	echo -e "${yellow_color}${bold_color}    Information: https://www.hackthebox.eu/home/pwnbox${end_color}"
	echo ""
}

# No parameter
if [[ "$1" == "" ]]; then
	usage
	exit 1
fi

root_user

# Checking if process already running
check_proc="$(ps -C "MassVulScan4HTB.sh" | grep -c "MassVulScan4HTB\.sh")"

if [[ ${check_proc} -gt "2" ]]; then
	echo -e "${red_color}[X] A process \"MassVulScan4HTB.sh\" is already running.${end_color}"
	exit 1
fi

# Cleaning old files
rm -rf nmap-input.temp.txt nmap-input.txt masscan-output.txt process_nmap_done.txt vulnerable_hosts.txt \
nmap-output.xml /tmp/nmap_temp-* 2>/dev/null

clear

##################################
# 1/4 Wait for host to be online #
##################################

echo -e "${blue_color}[-] Wait for host to be online...please, be patient!${end_color}"
while ! ping -c1 ${host} &>/dev/null; do
	echo -n -e "\r                                                                            "
	echo -n -e "${red_color}\r[X] Host still offline${end_color} - ${yellow_color}$(date)${end_color}"
	sleep 1
done

echo -e "${green_color}\r[V] Host Found!${end_color} - ${yellow_color}$(date)${end_color}              "

########################################
# 2/4 Using Masscan to find open ports #
########################################

echo -e "${blue_color}[-] Verifying Masscan parameters and running the tool...please, be patient!${end_color}"

if [[ $(id -u) = "0" ]]; then
	masscan --open ${ports} --source-port 40000 "${host}" -e "${interface}" --max-rate "${rate}" -oL masscan-output.txt
else
	sudo masscan --open ${ports} --source-port 40000 -iL "${hosts}" -e "${interface}" --max-rate "${rate}" -oL masscan-output.txt
fi

if [[ $? != "0" ]]; then
	echo -e "${error_color}[X] ERROR! Thanks to verify your parameters (hostname instead IPv4?). The script is ended.${end_color}"
	rm -rf masscan-output.txt
	exit 1
fi

echo -e "${green_color}[V] Masscan phase is ended.${end_color}"

if [[ -z masscan-output.txt ]]; then
	echo -e "${error_color}[X] ERROR! File \"masscan-output.txt\" disapeared! The script is ended.${end_color}"
	exit 1
fi

if [[ ! -s masscan-output.txt ]]; then
        echo -e "${green_color}[!] No ip with open TCP/UDP ports found, so, exit! ->${end_color}"
	rm -rf masscan-output.txt
	time_elapsed
	exit 0
	else
		tcp_ports="$(grep -c "^open tcp" masscan-output.txt)"
		udp_ports="$(grep -c "^open udp" masscan-output.txt)"
		nb_ports="$(grep -c ^open masscan-output.txt)"
		echo -e "${yellow_color}[I] host \"${host}\" has ${nb_ports} open ports:${end_color}"
		#grep ^open masscan-output.txt | awk '{ip[$4]++} END{for (i in ip) {print i " has " ip[i] " open port(s)"}}' | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4
fi

###########################################################################################
# 3/4 Using Nmap to identify open services and if they are vulnerable with vulners script #
###########################################################################################

# Folder for temporary Nmap file(s)
nmap_temp="$(mktemp -d /tmp/nmap_temp-XXXXXXXX)"

# Preparing the input file for Nmap
nmap_file(){
proto="$1"

# Source: http://www.whxy.org/book/mastering-kali-linux-advanced-pen-testing-2nd/text/part0103.html
grep "^open ${proto}" masscan-output.txt | awk '/.+/ { \
				if (!($4 in ips_list)) { \
				value[++i] = $4 } ips_list[$4] = ips_list[$4] $3 "," } END { \
				for (j = 1; j <= i; j++) { \
				printf("%s:%s:%s\n%s", $2, value[j], ips_list[value[j]], (j == i) ? "" : "\n") } }' | sed '/^$/d' | sed 's/.$//' >> nmap-input.temp.txt
}

rm -rf nmap-input.temp.txt

if [[ ${tcp_ports} -gt "0" ]]; then
	nmap_file tcp
fi

if [[ ${udp_ports} -gt "0" ]]; then
	nmap_file udp
fi

sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4 nmap-input.temp.txt > nmap-input.txt

cat nmap-input.txt

# Checking if vulners.com site is reachable
if [[ ${script} == "vulners" ]]; then
	check_vulners_api_status="$(nc -z -v -w 1 vulners.com 443 2>&1 | grep -oE '(succeeded!$|open$)' | sed 's/^succeeded!/open/')"

	if [[ ${check_vulners_api_status} == "open" ]]; then
		echo -e "${yellow_color}[I] Vulners.com site is reachable on port 443.${end_color}"
		else
			echo -e "${blue_color}${bold_color}Warning: Vulners.com site is NOT reachable on port 443. Please, check your firewall rules, dns configuration and your Internet link.${end_color}"
			echo -e "${blue_color}${bold_color}So, vulnerability check will be not possible, only opened ports will be present in the report.${end_color}"
	fi
fi

nb_nmap_process="$(sort -n nmap-input.txt | wc -l)"
date="$(date +%F_%H-%M-%S)"

# Function for parallel Nmap scans
parallels_scans(){
proto="$(echo "$1" | cut -d":" -f1)"
ip="$(echo "$1" | cut -d":" -f2)"
port="$(echo "$1" | cut -d":" -f3)"

if [[ $proto == "tcp" ]]; then
	nmap --max-retries 2 --max-rtt-timeout 500ms -p"${port}" -Pn -sT -sV -n --script ${script} -oA "${nmap_temp}/${ip}"_tcp_nmap-output "${ip}" > /dev/null 2>&1
	cp "${nmap_temp}/${ip}"_tcp_nmap-output.nmap "${report_folder}""${ip}_tcp_nmap-output_${date}.nmap"
	echo "${ip} (${proto}): Done" >> process_nmap_done.txt
	else
		nmap --max-retries 2 --max-rtt-timeout 500ms -p"${port}" -Pn -sU -sV -n --script ${script} -oA "${nmap_temp}/${ip}"_udp_nmap-output "${ip}" > /dev/null 2>&1
		cp "${nmap_temp}/${ip}"_udp_nmap-output.nmap "${report_folder}""${ip}_udp_nmap-output_${date}.nmap"
		echo "${ip} (${proto}): Done" >> process_nmap_done.txt
fi

nmap_proc_ended="$(grep "$Done" -co process_nmap_done.txt)"
pourcentage="$(awk "BEGIN {printf \"%.2f\n\", "${nmap_proc_ended}/${nb_nmap_process}*100"}")"
echo -n -e "\r                                                                                                         "
echo -n -e "${yellow_color}${bold_color}\r[I] Scan is done for ${ip} (${proto}) -> ${nmap_proc_ended}/${nb_nmap_process} Nmap process launched...(${pourcentage}%)${end_color}"
}

# Controlling the number of Nmap scanner to launch
if [[ ${nb_nmap_process} -ge "10" ]]; then
	max_job="10"
	echo -e "${blue_color}${bold_color}Warning: A lot of Nmap process to launch: ${nb_nmap_process}${end_color}"
	echo -e "${blue_color}[-] So, to no disturb your system, I will only launch ${max_job} Nmap process at time.${end_color}"
	else
		echo -e "${blue_color}${bold_color}[-] Launching ${nb_nmap_process} Nmap scanner(s)...${end_color}"
		max_job="${nb_nmap_process}"
fi

# Queue files
new_job(){
job_act="$(jobs | wc -l)"
while ((job_act >= ${max_job})); do
	job_act="$(jobs | wc -l)"
done
parallels_scans "${ip_to_scan}" &
}

# We are launching all the Nmap scanners in the same time
count="1"

rm -rf process_nmap_done.txt

while IFS=, read -r ip_to_scan; do
	new_job $i
	count="$(expr $count + 1)"
done < nmap-input.txt

wait

sleep 2 && tset

echo -e "${green_color}[V] Nmap phase is ended.${end_color}"

grep -E '(/tcp.*open|^Service.Info)' "${nmap_temp}/${host}_tcp_nmap-output.nmap" 2>/dev/null
grep -E '(/udp.*open|^Service.Info)' "${nmap_temp}/${host}_udp_nmap-output.nmap" 2>/dev/null

# Verifying vulnerabilities
vuln_hosts_count="$(for i in ${nmap_temp}/*.nmap; do tac "$i" | sed -n -e '/|_.*CVE-\|VULNERABLE/,/^Nmap/p' | tac ; done | grep "Nmap" | sort -u | grep -c "Nmap")"
vuln_ports_count="$(for i in ${nmap_temp}/*.nmap; do tac "$i" | sed -n -e '/|_.*CVE-\|VULNERABLE/,/^Nmap/p' | tac ; done | grep -Eoc '(/udp.*open|/tcp.*open)')"
vuln_hosts="$(for i in ${nmap_temp}/*.nmap; do tac "$i" | sed -n -e '/|_.*CVE-\|VULNERABLE/,/^Nmap/p' | tac ; done)"
vuln_hosts_ip="$(for i in ${nmap_temp}/*.nmap; do tac "$i" | sed -n -e '/|_.*CVE-\|VULNERABLE/,/^Nmap/p' | tac ; done | grep ^"Nmap scan report for" | cut -d" " -f5 | sort -u)"
vulnerabilities_count="$(for i in ${nmap_temp}/*.nmap; do grep -E '(CVE-|VULNERABLE)' "$i"; done | wc -l)"

if [[ ${vuln_hosts_count} != "0" ]]; then
	echo -e "${red_color}[X] ${vulnerabilities_count} potential vulnerabilitie(s) found.${end_color}"
	echo -e -n "${vuln_hosts_ip}\n" | while read line; do
		host="$(dig -x "${line}" +short)"
		echo "${line}" "${host}" >> vulnerable_hosts.txt
	done

	vuln_hosts_format="$(awk '{print $1 "\t" $NF}' vulnerable_hosts.txt |  sed 's/3(NXDOMAIN)/\No reverse DNS entry found/' | sort -t . -n -k1,1 -k2,2 -k3,3 -k4,4 | sort -u)"
	echo -e -n "\t----------------------------\n" > "${report_folder}vulnerable_hosts_details_${date}.txt"
	echo -e -n "Report date: $(date)\n" >> "${report_folder}vulnerable_hosts_details_${date}.txt"
	echo -e -n "Host(s) found: ${vuln_hosts_count}\n" >> "${report_folder}vulnerable_hosts_details_${date}.txt"
	echo -e -n "Port(s) found: ${vuln_ports_count}\n" >> "${report_folder}vulnerable_hosts_details_${date}.txt"
	echo -e -n "${vuln_hosts_format}\n" >> "${report_folder}vulnerable_hosts_details_${date}.txt"
	echo -e -n "All the details below." >> "${report_folder}vulnerable_hosts_details_${date}.txt"
	echo -e -n "\n\t----------------------------\n" >> "${report_folder}vulnerable_hosts_details_${date}.txt"
	echo -e -n "${vuln_hosts}\n" >> "${report_folder}vulnerable_hosts_details_${date}.txt"
else
	echo -e "${blue_color}No vulnerable host found... at first sight!.${end_color}"

fi

##########################
# 4/4 Generating reports #
##########################

nmap_bootstrap="./stylesheet/nmap-bootstrap.xsl"
vulnerable_report_name="${host}_vulnerabilities_"

if [[ -s ${report_folder}vulnerable_hosts_details_${date}.txt ]]; then
	mv ${report_folder}vulnerable_hosts_details_${date}.txt ${report_folder}${vulnerable_report_name}${date}.txt
	echo -e "${yellow_color}[I] All details on the vulnerabilities:"
	echo -e "${blue_color}${report_folder}${vulnerable_report_name}${date}.txt${end_color}"
fi

# Merging all the Nmap XML files to one big XML file
echo "<?xml version=\"1.0\"?>" > nmap-output.xml
echo "<!DOCTYPE nmaprun PUBLIC \"-//IDN nmap.org//DTD Nmap XML 1.04//EN\" \"https://svn.nmap.org/nmap/docs/nmap.dtd\">" >> nmap-output.xml
echo "<?xml-stylesheet href="https://svn.nmap.org/nmap/docs/nmap.xsl\" type="text/xsl\"?>" >> nmap-output.xml
echo "<!-- nmap results file generated by MassVulScan4HTB.sh -->" >> nmap-output.xml
echo "<nmaprun args=\"nmap --max-retries 2 --max-rtt-timeout 500ms -p[port(s)] -Pn -s(T|U) -sV -n --script ${script} [ip(s)]\" scanner=\"Nmap\" start=\"\" version=\"${nmap_version}\" xmloutputversion=\"1.04\">" >> nmap-output.xml
echo "<!--Generated by MassVulScan4HTB.sh--><verbose level=\"0\" /><debug level=\"0\" />" >> nmap-output.xml

for i in ${nmap_temp}/*.xml; do
	sed -n -e '/<host /,/<\/host>/p' "$i" >> nmap-output.xml
done

echo "<runstats><finished elapsed=\"\" exit=\"success\" summary=\"Nmap XML merge done at $(date); ${vuln_hosts_count} vulnerable host(s) found\" \
      time=\"\" timestr=\"\" /><hosts down=\"0\" total=\"${nb_hosts_nmap}\" up=\"${nb_hosts_nmap}\" /></runstats></nmaprun>" >> nmap-output.xml

# Using bootstrap to generate a beautiful HTML file (report)
xsltproc -o "${report_folder}${host}_${date}.html" "${nmap_bootstrap}" nmap-output.xml 2>/dev/null

# End of script
echo -e "${yellow_color}[I] Global HTML report generated:"
echo -e "${blue_color}${report_folder}${global_report_name}${date}.html${end_color}"
echo -e "${yellow_color}[I] Nmap scans:"
echo -e "${blue_color}$(ls ${report_folder}${host}* | grep -E '(tcp_nmap|udp_nmap)' | grep ${date})${end_color}"
echo -e "${green_color}[V] Report phase is ended, bye!${end_color}"

rm -rf nmap-input.temp.txt nmap-input.txt masscan-output.txt process_nmap_done.txt vulnerable_hosts.txt \
nmap-output.xml "${nmap_temp}" 2>/dev/null

time_elapsed

exit 0
