#!/bin/bash

#-Metadata----------------------------------------------------#
#  Filename: sub.sh (v1.0.0)   (Update: 2020-07-27)           #
#-Info--------------------------------------------------------#
# Subdomain Detect Script			     	     			  #
#-URL---------------------------------------------------------#
# https://git.io/-----                                        #
#-------------------------------------------------------------#

GREEN="\033[1;32m"
BLUE="\033[1;36m"
RED="\033[1;31m"
RESET="\033[0m"



function banner(){
	echo -e "${BLUE}[i] Subdomain Detect Script ${RESET}"
	echo -e "[t] Twitter => https://twitter.com/r0cky57347427"
	echo -e "[g] Github => https://github.com/r0ckysec/sub.sh"
	echo -e "${BLUE}[#] bash sub.sh -s domain ${RESET}"
	echo -e "${BLUE}[#] curl -sL https://git.io/----- | bash /dev/stdin -a domain ${RESET}"
	echo -e "█████████████████████████████████████████████████████████████████"
}
#############################################################################################################
function 1crt(){
	curl -s "https://crt.sh/?q=%25.$1&output=json"| jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u | grep -o "\w.*$1" > crt_$1.txt
	echo -e "[+] Crt.sh Over => $(wc -l crt_$1.txt|awk '{ print $1}')"
}
function 2warchive(){
	curl -s "http://web.archive.org/cdx/search/cdx?url=*.$1/*&output=text&fl=original&collapse=urlkey" | sort | sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' |sort -u > warchive_$1.txt
	echo "[+] Web.Archive.org Over => $(wc -l warchive_$1.txt|awk '{ print $1}')"
}
function 3dnsbuffer(){
	curl -s "https://dns.bufferover.run/dns?q=.$1" | jq -r .FDNS_A[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$1" | sort -u > dnsbuffer_$1.txt
	curl -s "https://dns.bufferover.run/dns?q=.$1" | jq -r .RDNS[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$1" | sort -u >> dnsbuffer_$1.txt 
	curl -s "https://tls.bufferover.run/dns?q=.$1" | jq -r .Results 2>/dev/null | cut -d ',' -f3 |grep -o "\w.*$1"| sort -u >> dnsbuffer_$1.txt 
	sort -u dnsbuffer_$1.txt -o dnsbuffer_$1.txt
	echo "[+] Dns.bufferover.run Over => $(wc -l dnsbuffer_$1.txt|awk '{ print $1}')"
}
function 4threatcrowd(){
	curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$1"|jq -r '.subdomains' 2>/dev/null |grep -o "\w.*$1" > threatcrowd_$1.txt
	echo "[+] Threatcrowd.org Over => $(wc -l threatcrowd_$1.txt|awk '{ print $1}')"
}
function 5hackertarget(){
	curl -s "https://api.hackertarget.com/hostsearch/?q=$1"|grep -o "\w.*$1"> hackertarget_$1.txt
	echo "[+] Hackertarget.com Over => $(wc -l hackertarget_$1.txt | awk '{ print $1}')"
}
function 6certspotter(){
	curl -s "https://certspotter.com/api/v0/certs?domain=$1" | jq -r '.[].dns_names[]' 2>/dev/null | grep -o "\w.*$1" | sort -u > certspotter_$1.txt
	echo "[+] Certspotter.com Over => $(wc -l certspotter_$1.txt | awk '{ print $1}')"
}
function 7anubisdb(){
	curl -s "https://jldc.me/anubis/subdomains/$1" | jq -r '.' 2>/dev/null | grep -o "\w.*$1" > anubisdb_$1.txt
	echo "[+] Anubis-DB(jonlu.ca) Over => $(wc -l anubisdb_$1.txt|awk '{ print $1}')"
}
function 8virustotal(){
	curl -s "https://www.virustotal.com/ui/domains/$1/subdomains?limit=40"|jq -r '.' 2>/dev/null |grep id|grep -o "\w.*$1"|cut -d '"' -f3|egrep -v " " > virustotal_$1.txt
	echo "[+] Virustotal Over => $(wc -l virustotal_$1.txt|awk '{ print $1}')"
}
function 9alienvault(){
	curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$1/passive_dns"|jq '.passive_dns[].hostname' 2>/dev/null |grep -o "\w.*$1"|sort -u > alienvault_$1.txt
	echo "[+] Alienvault(otx) Over => $(wc -l alienvault_$1.txt|awk '{ print $1}')"
}
function 10urlscan(){
	curl -s "https://urlscan.io/api/v1/search/?q=domain:$1"|jq '.results[].page.domain' 2>/dev/null |grep -o "\w.*$1"|sort -u > urlscan_$1.txt
	echo "[+] Urlscan.io Over => $(wc -l urlscan_$1.txt|awk '{ print $1}')"
}

# 404
function 11threatminer(){
	curl -s "https://api.threatminer.org/v2/domain.php?q=$1&rt=5" | jq -r '.results[]' 2>/dev/null |grep -o "\w.*$1"|sort -u > threatminer_$1.txt
	echo "[+] Threatminer Over => $(wc -l threatminer_$1.txt|awk '{ print $1}')"
}
# 403
function 12entrust(){
	curl -s "https://ctsearch.entrust.com/api/v1/certificates?fields=subjectDN&domain=$1&includeExpired=false&exactMatch=false&limit=5000" | jq -r '.[].subjectDN' 2>/dev/null |sed 's/cn=//g'|grep -o "\w.*$1"|sort -u > entrust_$1.txt
	echo "[+] Entrust.com Over => $(wc -l entrust_$1.txt|awk '{ print $1}')"
}

function 13riddler() {
	curl -s "https://riddler.io/search/exportcsv?q=pld:$1"| grep -o "\w.*$1"|awk -F, '{print $6}'|sort -u > riddler_$1.txt
	#curl -s "https://riddler.io/search/exportcsv?q=pld:$1"|cut -d "," -f6|grep $1|sort -u >riddler_$1.txt
	echo "[+] Riddler.io Over => $(wc -l riddler_$1.txt|awk '{ print $1}')"
}

function 14dnsdumpster() {
	cmdtoken=$(curl -ILs https://dnsdumpster.com | grep csrftoken | cut -d " " -f2 | cut -d "=" -f2 | tr -d ";")
	curl -s --header "Host:dnsdumpster.com" --referer https://dnsdumpster.com --user-agent "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" --data "csrfmiddlewaretoken=$cmdtoken&targetip=$1" --cookie "csrftoken=$cmdtoken; _ga=GA1.2.1737013576.1458811829; _gat=1" https://dnsdumpster.com > dnsdumpster.html

	cat dnsdumpster.html|grep "https://api.hackertarget.com/httpheaders"|grep -o "\w.*$1"|cut -d "/" -f7|sort -u > dnsdumper_$1.txt
	rm dnsdumpster.html
	echo "[+] Dnsdumpster Over => $(wc -l dnsdumper_$1.txt|awk '{ print $1}')"
}
function 15findomain() {
	findomain -t $1 -u findomain_$1.txt &>/dev/null
	if [ $? -ne 0 ]; then
		echo 'eg: findomain执行错误!'
		return
	fi
	echo "[+] Findomain Over => $(wc -l findomain_$1.txt | awk '{ print $1}')"
}
function 16subfinder() {
	subfinder -config subtools/config/config.yaml -silent -d $1 -o subfinder_$1.txt &>/dev/null
	if [ $? -ne 0 ]; then
		echo 'eg: subfinder执行错误!'
		return
	fi
	echo "[+] Subfinder Over => $(wc -l subfinder_$1.txt|awk '{ print $1}')"
}
function 17amass_passive() {
	amass enum -passive -norecursive -noalts -d $1 -o amass_passive_$1.txt &>/dev/null
	if [ $? -ne 0 ]; then
		echo 'eg: amass_passive执行错误!'
		return
	fi
	echo "[+] Amass Passive Over => $(wc -l amass_passive_$1.txt|awk '{ print $1}')"
}
function 17amass_active() {
	#amass enum -active -brute -d $1 -o amass_active_$1.txt &>/dev/null
	touch amass_active_$1.txt
	echo "[+] Amass Active Over => $(wc -l amass_active_$1.txt|awk '{ print $1}')"
}
function 18assetfinder() {
	assetfinder --subs-only $1 > assetfinder_$1.txt
	if [ $? -ne 0 ]; then
		echo 'eg: assetfinder执行错误!'
		return
	fi
	echo "[+] Assetfinder Over => $(wc -l  assetfinder_$1.txt|awk '{ print $1}')"
}
function 19rapiddns() {
	curl -s "https://rapiddns.io/subdomain/$1?full=1#result" | grep -oaEi "https?://[^\"\\'> ]+" | grep $1 | cut -d "/" -f3 | sort -u >rapiddns_$1.txt
	echo "[+] Rapiddns Over => $(wc -l rapiddns_$1.txt|awk '{ print $1}')"
}
function 20subDomainsBrute() {
	path=`pwd`
	cd subtools/subDomainsBrute/
	#python3 -m pip install aiodns &>/dev/null
	python3 subDomainsBrute.py --full $1 -o tmp_$1.txt &>/dev/null
	if [ $? -ne 0 ]; then
		echo 'eg: subDomainsBrute执行错误!'
		return
	fi
	cat tmp_$1.txt | awk '{ print $1}' > subDomainsBrute_$1.txt
	rm -rf tmp_$1.txt
	cp subDomainsBrute_$1.txt ${path}/
	echo "[+] subDomainsBrute Over => $(wc -l subDomainsBrute_$1.txt|awk '{ print $1}')"
}
function 21Sublist3r() {
	path=`pwd`
	cd subtools/Sublist3r/
	python3 sublist3r.py -t 100 -o sublist3r_$1.txt -d $1 &>/dev/null
	if [ $? -ne 0 ]; then
		echo 'eg: Sublist3r执行错误!'
		return
	fi
	cp sublist3r_$1.txt ${path}/
	echo "[+] Sublist3r Over => $(wc -l sublist3r_$1.txt|awk '{ print $1}')"
}
function 22knock() {
	path=`pwd`
	cd subtools/knock-4.1/
	# 清除之前的记录
	rm -rf *.json
	python knockpy/knockpy.py -j $1 &>/dev/null
	if [ $? -ne 0 ]; then
		echo 'eg: knock执行错误!'
		return
	fi
	cat *.json | jq -r .found.subdomain[] > knock_$1.txt
	cp knock_$1.txt ${path}/
	echo "[+] knock Over => $(wc -l knock_$1.txt|awk '{ print $1}')"
}
function 23shuffledns() {
	shuffledns -massdns massdns/bin/massdns -d $1 -w subtools/dict/subnames.txt -r subtools/dict/resolvers.txt -silent -o shuffledns_$1.txt &>/dev/null
	if [ $? -ne 0 ]; then
		echo 'eg: shuffledns执行错误!'
		return
	fi
	echo "[+] shuffledns Over => $(wc -l shuffledns_$1.txt|awk '{ print $1}')"
}
function 24theHarvester() {
	path=`pwd`
	cd subtools/theHarvester/
	python3 theHarvester.py -d $1 -c -b all -f tmp_domain &>/dev/null
	if [ $? -ne 0 ]; then
		echo 'eg: theHarvester执行错误!'
		return
	fi
	xmllint --format tmp_domain.xml &>/dev/null
	if [ $? -ne 0 ]; then
		echo '</theHarvester>' >> tmp_domain.xml
	fi
	xmllint --xpath "//hostname/text()" tmp_domain.xml > theHarvester_$1.txt
	cp theHarvester_$1.txt ${path}/
	echo "[+] theHarvester Over => $(wc -l theHarvester_$1.txt|awk '{ print $1}')"
}
#############################################################################################################
function commonToolInstall(){
	
	result=$(go version | grep go1.6)
	if [ "$result" ]; then
		echo 'go版本过低，正在升级...'
		#wget https://golang.org/dl/go1.15.8.linux-amd64.tar.gz -O /tmp/go1.15.8.linux-amd64.tar.gz
		#替换自己github
		wget https://github.com/r0ckysec/subtools/releases/latest/download/go1.15.8.linux-amd64.tar.gz -O /tmp/go1.15.8.linux-amd64.tar.gz
		tar -zxf /tmp/go1.15.8.linux-amd64.tar.gz -C /usr/local/
		rm -rf /tmp/go1.15.8.linux-amd64.tar.gz
		ln -snf /usr/local/go /usr/lib/go
		cp /usr/lib/go/bin/go /usr/bin/
		echo "export GO111MODULE=on" >> ~/.bashrc
		echo "export GOPROXY=https://mirrors.aliyun.com/goproxy/,direct" >> ~/.bashrc
		echo "export GOROOT=/usr/local/go" >> ~/.bashrc
		echo "export GOPATH=$HOME/go" >> ~/.bashrc
		echo "export PATH=$PATH:$GOROOT/bin:$GOPATH/bin" >> ~/.bashrc
		source ~/.bashrc
		result=$(go version | grep go1.6)
		if [ "$result" ]; then
			echo 'go升级失败 -> '$result
		else
			echo 'go升级成功 -> '`go version`
		fi
	else
		echo `go version`
	fi
	# 国内镜像加速    https://goproxy.cn,direct
	#go env -w GO111MODULE=on
	#go env -w GOPROXY=https://mirrors.aliyun.com/goproxy/,direct
	export GO111MODULE=on
	export GOPROXY=https://mirrors.aliyun.com/goproxy/,direct
	# cannot download, $GOPATH not set.
	# 解决，环境变量设置
	# nano ~/.bashrc or nano ~/.zshrc
	export GOPATH=$HOME/go
	export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
	# --------
	# Install httprobe
	if [ -e ~/go/bin/httprobe ] || [ -e /usr/local/bin/httprobe ] || [ -e ~/go-workspace/bin/httprobe ] || [ -e ~/gopath/bin/httprobe ] ; then
		echo -e "${BLUE}[!] httprobe already exists ${RESET}"
	else 
		go get -u github.com/tomnomnom/httprobe
		sudo mv ~/go/bin/httprobe /usr/local/bin/httprobe
		sudo chmod +x /usr/local/bin/httprobe
		if [ -e ~/go/bin/httprobe ] || [ -e /usr/local/bin/httprobe ] || [ -e ~/go-workspace/bin/httprobe ] || [ -e ~/gopath/bin/httprobe ] ; then
			continue
		else
			echo -e "${RED}[!] httprobe go get failed ${RESET}"
			#wget https://github.com/tomnomnom/httprobe/releases/download/v0.1.2/httprobe-linux-amd64-0.1.2.tgz -O /tmp/httprobe-linux-amd64-0.1.2.tgz
			#替换自己github
			wget https://github.com/r0ckysec/subtools/releases/latest/download/httprobe-linux-amd64-0.1.2.tgz -O /tmp/httprobe-linux-amd64-0.1.2.tgz
			tar -zxf /tmp/httprobe-linux-amd64-0.1.2.tgz -C /usr/local/bin/
			sudo chmod +x /usr/local/bin/httprobe
			rm -rf /tmp/httprobe-linux-amd64-0.1.2.tgz
		fi
		# wget 方式
		#wget https://github.com/tomnomnom/httprobe/releases/download/v0.1.2/httprobe-linux-amd64-0.1.2.tgz -O /tmp/httprobe-linux-amd64-0.1.2.tgz
		#tar -zxf /tmp/httprobe-linux-amd64-0.1.2.tgz -C /usr/local/bin/
		#sudo chmod +x /usr/local/bin/httprobe
		#rm -rf /tmp/httprobe-linux-amd64-0.1.2.tgz
		
		if [ -e ~/go/bin/httprobe ] || [ -e /usr/local/bin/httprobe ] || [ -e ~/go-workspace/bin/httprobe ] || [ -e ~/gopath/bin/httprobe ] ; then
			echo -e "${GREEN}[!] httprobe installed ${RESET}"
		else
			echo -e "${RED}[!] httprobe install failed ${RESET}"
			exit -1
		fi
	fi
	# --------
	# Install subfinder
	if [ -e ~/go/bin/subfinder ] || [ -e /usr/local/bin/subfinder ] || [ -e ~/go-workspace/bin/subfinder ] || [ -e ~/gopath/bin/subfinder ] ; then
		echo -e "${BLUE}[!] Subfinder already exists ${RESET}"
	else 
		go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder
		sudo mv ~/go/bin/subfinder /usr/local/bin/subfinder
		sudo chmod +x /usr/local/bin/subfinder
		if [ -e ~/go/bin/subfinder ] || [ -e /usr/local/bin/subfinder ] || [ -e ~/go-workspace/bin/subfinder ] || [ -e ~/gopath/bin/subfinder ] ; then
			continue
		else
			echo -e "[!] Subfinder go get failed"
			#wget https://github.com/projectdiscovery/subfinder/releases/download/v2.4.6/subfinder_2.4.6_linux_amd64.tar.gz -O /tmp/subfinder_linux_amd64.tar.gz
			#替换自己github
			wget https://github.com/r0ckysec/subtools/releases/latest/download/subfinder_2.4.6_linux_amd64.tar.gz -O /tmp/subfinder_linux_amd64.tar.gz
			tar -zxf /tmp/subfinder_linux_amd64.tar.gz -C /usr/local/bin/
			sudo chmod +x /usr/local/bin/subfinder
			rm -rf /tmp/subfinder_linux_amd64.tar.gz
		fi
		if [ -e ~/go/bin/subfinder ] || [ -e /usr/local/bin/subfinder ] || [ -e ~/go-workspace/bin/subfinder ] || [ -e ~/gopath/bin/subfinder ] ; then
			echo -e "${GREEN}[!] Subfinder installed ${RESET}"
		else
			echo -e "${RED}[!] Subfinder install failed ${RESET}"
			exit -1
		fi
	fi
	# --------
	# Install assetfinder
	if [ -e ~/go/bin/assetfinder ] || [ -e /usr/local/bin/assetfinder ] || [ -e ~/go-workspace/bin/assetfinder ] || [ -e ~/gopath/bin/assetfinder ] ; then
		echo -e "${BLUE}[!] Assetfinder already exists ${RESET}"
	   
	else 
		# go get -u github.com/tomnomnom/assetfinder
		go get -u github.com/r0ckysec/assetfinder
		sudo mv ~/go/bin/assetfinder /usr/local/bin/assetfinder
		sudo chmod +x /usr/local/bin/assetfinder
		if [ -e ~/go/bin/assetfinder ] || [ -e /usr/local/bin/assetfinder ] || [ -e ~/go-workspace/bin/assetfinder ] || [ -e ~/gopath/bin/assetfinder ] ; then
			echo -e "${GREEN}[!] Assetfinder installed ${RESET}"
		else
			echo -e "${RED}[!] Assetfinder install failed ${RESET}"
			exit -1
		fi
	fi
	# --------
	# Install findomain
	if [ -e /usr/local/bin/findomain ] ; then
	   
		echo -e "${BLUE}[!] Findomain already exists ${RESET}"
	   
	else 
		case "$(uname -a)" in
			*Debian*|*Ubuntu*|*Linux*|*Fedora*)
			 	#wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux
				#替换自己github
				wget https://github.com/r0ckysec/subtools/releases/latest/download/findomain-linux
				sudo chmod +x findomain-linux
				sudo mv findomain-linux /usr/local/bin/findomain
				;;
			*)
				echo "OS Not Linux";
				;;
		esac
		if [ -e /usr/local/bin/findomain ] ; then
			echo -e "${GREEN}[!] Findomain installed ${RESET}"
		else
			echo -e "${RED}[!] Findomain install failed ${RESET}"
			exit -1
		fi
	fi
	# --------
	# Install amass
	if [ -e /usr/bin/amass ] || [ -e /usr/local/bin/amass ] || [ -e ~/go/bin/amass ] ||  [ -e ~/go-workspace/bin/amass ] || [ -e ~/gopath/bin/amass ] ; then
	   
		echo -e "${BLUE}[!] Amass already exists ${RESET}"
	   
	else 
		case "$(uname -a)" in
			*Debian*|*Ubuntu*|*Linux*|*Fedora*)
				
				#wget https://github.com/OWASP/Amass/releases/latest/download/amass_linux_amd64.zip -O /tmp/amass.zip
				#替换自己github
				wget https://github.com/r0ckysec/subtools/releases/latest/download/amass_linux_amd64.zip -O /tmp/amass.zip
				unzip /tmp/amass.zip -d /tmp/
				sudo mv /tmp/amass_linux_amd64/amass /usr/local/bin/amass
				sudo chmod +x /usr/local/bin/amass
				rm -rf /tmp/amass_linux_amd64/ /tmp/amass.zip
				#git clone https://github.com/OWASP/Amass.git
				#go get -v -u github.com/OWASP/Amass/v3/...
				;;
			*)
				echo "OS Not Fedora";
				;;
		esac
		if [ -e /usr/bin/amass ] || [ -e /usr/local/bin/amass ] || [ -e ~/go/bin/amass ] ||  [ -e ~/go-workspace/bin/amass ] || [ -e ~/gopath/bin/amass ] ; then
			echo -e "${GREEN}[!] Amass installed ${RESET}"
		else
			echo -e "${RED}[!] Amass install failed ${RESET}"
			exit -1
		fi
	fi
	# --------
	# Install shuffledns
	if [ -e /usr/bin/shuffledns ] || [ -e /usr/local/bin/shuffledns ] || [ -e ~/go/bin/shuffledns ] ||  [ -e ~/go-workspace/bin/shuffledns ] || [ -e ~/gopath/bin/shuffledns ] ; then
	   
		echo -e "${BLUE}[!] Shuffledns already exists ${RESET}"
	   
	else 
		go get -v github.com/projectdiscovery/shuffledns/cmd/shuffledns
		# wget https://github.com/projectdiscovery/shuffledns/releases/latest/download/shuffledns_1.0.4_linux_amd64.tar.gz
		# tar -xzvf shuffledns_1.0.4_linux_amd64.tar.gz -O /tmp/
		sudo mv ~/go/bin/shuffledns /usr/local/bin/shuffledns
		sudo chmod +x /usr/local/bin/shuffledns
		if [ -e /usr/bin/shuffledns ] || [ -e /usr/local/bin/shuffledns ] || [ -e ~/go/bin/shuffledns ] ||  [ -e ~/go-workspace/bin/shuffledns ] || [ -e ~/gopath/bin/shuffledns ] ; then
			echo -e "[!] Shuffledns go get failed"
		else
			#wget https://github.com/projectdiscovery/shuffledns/releases/download/v1.0.4/shuffledns_1.0.4_linux_amd64.tar.gz -O /tmp/shuffledns_1.0.4_linux_amd64.tar.gz
			#替换自己github
			wget https://github.com/r0ckysec/subtools/releases/latest/download/shuffledns_1.0.4_linux_amd64.tar.gz -O /tmp/shuffledns_1.0.4_linux_amd64.tar.gz
			tar -zxf /tmp/shuffledns_1.0.4_linux_amd64.tar.gz -C /usr/local/bin/
			sudo chmod +x /usr/local/bin/shuffledns
			rm -rf /tmp/shuffledns_1.0.4_linux_amd64.tar.gz
		fi
		if [ -e /usr/bin/shuffledns ] || [ -e /usr/local/bin/shuffledns ] || [ -e ~/go/bin/shuffledns ] ||  [ -e ~/go-workspace/bin/shuffledns ] || [ -e ~/gopath/bin/shuffledns ] ; then
			echo -e "${GREEN}[!] Shuffledns installed ${RESET}"
		else
			echo -e "${RED}[!] Shuffledns install failed ${RESET}"
			exit -1
		fi
	fi
	
	# Install massdns
	if [ -e massdns/bin/massdns ] ; then
		echo -e "${BLUE}[!] Massdns already exists ${RESET}"
	else 
		# git clone https://github.com/blechschmidt/massdns.git
		#替换自己github
		git clone https://github.com/r0ckysec/massdns.git
		cd massdns/
		make
		cd ..
		if [ -e massdns/bin/massdns ] ; then
			echo -e "${GREEN}[!] Massdns installed ${RESET}"
		else
			echo -e "${RED}[!] Massdns install failed ${RESET}"
			exit -1
		fi
	fi
	
	# Install subtools
	if [ -d subtools ] ; then
		echo -e "${BLUE}[!] Subtools already exists ${RESET}"
	else 
		git clone https://github.com/r0ckysec/subtools.git
		echo -e "${GREEN}[!] Subtools installed ${RESET}"
	fi
	
	# 再次检验
	if [ -e ~/go/bin/httprobe ] || [ -e /usr/local/bin/httprobe ] || [ -e ~/go-workspace/bin/httprobe ] || [ -e ~/gopath/bin/httprobe ] ; then
		echo -e "[${GREEN}True${RESET}] httprobe already exists"
	else
		echo -e "${RED}[!] httprobe not exists ${RESET}"
		exit -1
	fi

	if [ -e ~/go/bin/subfinder ] || [ -e /usr/local/bin/subfinder ] || [ -e ~/go-workspace/bin/subfinder ] || [ -e ~/gopath/bin/subfinder ] ; then
		echo -e "[${GREEN}True${RESET}] Subfinder already exists"
	else
		echo -e "${RED}[!] Subfinder not exists ${RESET}"
		exit -1
	fi

	if [ -e ~/go/bin/assetfinder ] || [ -e /usr/local/bin/assetfinder ] || [ -e ~/go-workspace/bin/assetfinder ] || [ -e ~/gopath/bin/assetfinder ] ; then
		echo -e "[${GREEN}True${RESET}] Assetfinder already exists"
	else
		echo -e "${RED}[!] Assetfinder not exists ${RESET}"
		exit -1
	fi

	if [ -e /usr/local/bin/findomain ] ; then
		echo -e "[${GREEN}True${RESET}] Findomain already exists"
	   
	else
		echo -e "${RED}[!] Findomain not exists ${RESET}"
		exit -1
	fi

	if [ -e /usr/bin/amass ] || [ -e /usr/local/bin/amass ] || [ -e ~/go/bin/amass ] ||  [ -e ~/go-workspace/bin/amass ] || [ -e ~/gopath/bin/amass ] ; then
	   
		echo -e "[${GREEN}True${RESET}] Amass already exists"
	   
	else
		echo -e "${RED}[!] Amass not exists ${RESET}"
		exit -1
	fi
	
	if [ -e /usr/bin/shuffledns ] || [ -e /usr/local/bin/shuffledns ] || [ -e ~/go/bin/shuffledns ] ||  [ -e ~/go-workspace/bin/shuffledns ] || [ -e ~/gopath/bin/shuffledns ] ; then
	   
		echo -e "[${GREEN}True${RESET}] Shuffledns already exists"
	   
	else
		echo -e "${RED}[!] Shuffledns not exists ${RESET}"
		exit -1
	fi
	
	if [ -e massdns/bin/massdns ] ; then
		echo -e "[${GREEN}True${RESET}] Massdns already exists"
	else
		echo -e "${RED}[!] Massdns not exists ${RESET}"
		exit -1
	fi
	if [ -d subtools ] ; then
		echo -e "[${GREEN}True${RESET}] Subtools already exists"
	else 
		echo -e "${RED}[!] Massdns not exists ${RESET}"
		exit -1
	fi
}
#############################################################################################################
function installDebian(){ #Kali and Parrot Os
	sudo apt-get update -y
	sudo apt list --upgradable
	sudo apt install jq -y;
	sudo apt install amass -y;
	sudo apt install parallel -y;
	sudo apt install golang -y;
	sudo apt install git -y;
	sudo apt install libxml2-utils -y
	sudo apt-get install python-dnspython -y
	echo -e "${GREEN}[!] Debian Tool Installed ${RESET}"
	commonToolInstall;
	echo -e "${GREEN}[!] Common Tool Installed ${RESET}"
	source ~/.bashrc ~/.zshrc;
}
function installOSX(){
	brew update
	brew install jq
	brew install findomain
	brew tap caffix/amass
	brew install amass
	brew install parallel
	brew install go
	brew install git
	echo -e "${GREEN}[!] MAC-OSX Tool Installed ${RESET}"
	commonToolInstall
	brew cleanup
	source ~/.bashrc ~/.zshrc;
}
function installFedora(){
	sudo yum -y update
	sudo yum install jq -y;
	sudo yum install parallel -y;
	sudo yum install golang -y;
	sudo yum install git -y;
	echo -e "${GREEN}[!] Fedora Tool Installed ${RESET}"
	commonToolInstall

	source ~/.bashrc ~/.zshrc;
}

function install(){
	case "$(uname -a)" in
		*Debian*|*Ubuntu*|*Linux*)
			installDebian;
			;;
		*Fedora*)
			installFedora;
			;;
		*Darwin*)
			installOSX;
			;;
		*)
			echo "Unable to detect an operating system that is compatible with Sub.sh...";
			;;
	esac
	echo "  "
	echo "[+] Installation Complete jq,parallel,go,git,httprobe,subfinder,assetfinder,findomain,amass,shuffledns,massdns,subtools";
	
}
#############################################################################################################
function subsave(){
	cat no_resolve_$1.txt|httprobe -c 50 > httprobe_$1.txt
	cat httprobe_$1.txt|cut -d "/" -f3|sort -u|tee $1.txt
	#-----------------------------------------------------------------------------------
	echo -e "█████████████████████████████████████████████████████████████████"
	echo -e "[*] Detect Subdomain $(wc -l no_resolve_$1.txt|awk '{ print $1}' )" "=> ${1}"
	echo -e "[+] File Location : "$(pwd)/"no_resolve_$1.txt"
	echo -e "[*] Detect Alive Subdomain $(wc -l $1.txt|awk '{ print $1 }' )" "=> ${1}"
	echo -e "[+] File Location : "$(pwd)/"$1.txt"
	echo -e "${GREEN}[H] Httprobe File Location : "$(pwd)/"httprobe_$1.txt ${RESET}"
}
#############################################################################################################
while [[ "${#}" -gt 0  ]]; do
args="${1}";
  	case "$( echo ${args} | tr '[:upper:]' '[:lower:]' )" in

		-s|--speed|--small)
			banner
			export -f 1crt  && export -f 2warchive && export -f 3dnsbuffer  && export -f 4threatcrowd  && export -f 5hackertarget  && export -f 6certspotter && export -f 7anubisdb && export -f 8virustotal && export -f 9alienvault && export -f 10urlscan && export -f 11threatminer && export -f 12entrust && export -f 13riddler && export -f 14dnsdumpster && export -f 19rapiddns

			parallel ::: 1crt 2warchive 3dnsbuffer 4threatcrowd 5hackertarget 6certspotter 7anubisdb 8virustotal 9alienvault 10urlscan 11threatminer 12entrust 13riddler 14dnsdumpster 19rapiddns ::: $2	
			
			echo "———————————————————————— $2 SUBDOMAIN—————————————————————————————————"
			cat crt_$2.txt warchive_$2.txt dnsbuffer_$2.txt threatcrowd_$2.txt hackertarget_$2.txt certspotter_$2.txt anubisdb_$2.txt virustotal_$2.txt alienvault_$2.txt urlscan_$2.txt threatminer_$2.txt entrust_$2.txt riddler_$2.txt dnsdumper_$2.txt rapiddns_$2.txt | sort -u | grep -v "@" | egrep -v "//|:|,| |_|\|/"|grep -o "\w.*$2"|tee no_resolve_$2.txt
			echo "- - - - - - - - - - - - - $2 ALIVE SUBDOMAIN - - - - - - - - - - - - -"
			rm crt_$2.txt warchive_$2.txt dnsbuffer_$2.txt threatcrowd_$2.txt hackertarget_$2.txt certspotter_$2.txt anubisdb_$2.txt virustotal_$2.txt alienvault_$2.txt urlscan_$2.txt threatminer_$2.txt entrust_$2.txt riddler_$2.txt dnsdumper_$2.txt rapiddns_$2.txt
			subsave $2
			shift
			;;

		-a|--all)
			banner
			export -f 1crt && export -f 2warchive && export -f 3dnsbuffer && export -f 4threatcrowd && export -f 5hackertarget && export -f 6certspotter && export -f 7anubisdb && export -f 8virustotal && export -f 9alienvault && export -f 10urlscan && export -f 11threatminer && export -f 12entrust && export -f 13riddler && export -f 14dnsdumpster && export -f 15findomain && export -f 16subfinder && export -f 17amass_passive && export -f 17amass_active && export -f 18assetfinder && export -f 19rapiddns && export -f 20subDomainsBrute && export -f 21Sublist3r && export -f 22knock && export -f 23shuffledns && export -f 24theHarvester

			parallel ::: 1crt 2warchive 3dnsbuffer 4threatcrowd 5hackertarget 6certspotter 7anubisdb 8virustotal 9alienvault 10urlscan 11threatminer 12entrust 13riddler 14dnsdumpster 15findomain 16subfinder 17amass_passive 17amass_active 18assetfinder 19rapiddns 20subDomainsBrute 21Sublist3r 22knock 24theHarvester ::: $2	
			
			# 单独执行 放在 parallel 中执行会错误，原因未知
			23shuffledns $2

			echo "———————————————————————— $2 SUBDOMAIN—————————————————————————————————"
			cat crt_$2.txt warchive_$2.txt dnsbuffer_$2.txt threatcrowd_$2.txt hackertarget_$2.txt certspotter_$2.txt anubisdb_$2.txt virustotal_$2.txt alienvault_$2.txt urlscan_$2.txt threatminer_$2.txt entrust_$2.txt riddler_$2.txt dnsdumper_$2.txt findomain_$2.txt subfinder_$2.txt amass_passive_$2.txt amass_active_$2.txt assetfinder_$2.txt rapiddns_$2.txt subDomainsBrute_$2.txt sublist3r_$2.txt knock_$2.txt shuffledns_$2.txt theHarvester_$2.txt | sort -u| grep -v "@" | egrep -v "//|:|,| |_|\|/"|grep -o "\w.*$2"|tee no_resolve_$2.txt

			echo "- - - - - - - - - - - - - $2 ALIVE SUBDOMAIN - - - - - - - - - - - - -"
			
			rm crt_$2.txt warchive_$2.txt dnsbuffer_$2.txt threatcrowd_$2.txt hackertarget_$2.txt certspotter_$2.txt anubisdb_$2.txt virustotal_$2.txt alienvault_$2.txt urlscan_$2.txt threatminer_$2.txt entrust_$2.txt riddler_$2.txt dnsdumper_$2.txt findomain_$2.txt subfinder_$2.txt amass_passive_$2.txt amass_active_$2.txt assetfinder_$2.txt rapiddns_$2.txt subDomainsBrute_$2.txt sublist3r_$2.txt knock_$2.txt shuffledns_$2.txt theHarvester_$2.txt

			subsave $2
			shift
			;;

		-i|--install)
			banner
			install
			shift
			;;

		-h|--help|*)
			echo -e "Usage : "
			echo -e "  -i | --install   sub.sh required tool install"
			echo -e "  -s | --small     Crt, Warchive, Dnsbuffer, Threatcrowd, Hackertarget, Certspotter, Abubis-DB, Virustotal,Alienvault, Urlscan, Threatminer, entrust, Riddler, Dnsdumpster Rapiddns"
			echo -e "  -a | --all       Crt, Web-Archive, Dnsbuffer, Threatcrowd, Hackertarget, Certspotter, Anubisdb, Virustotal, Alienvault, Urlscan, Threatminer,  Entrust, Riddler, Dnsdumpster, Findomain, Subfinder, Amass, Assetfinder, Rapiddns"
			echo -e "  bash sub.sh -s testfire.net"
			echo -e "  bash sub.sh -a testfire.net"
			echo -e "  curl -sL https://git.io/JesKK | bash /dev/stdin -s webscantest.com"
			echo -e "  curl -sL https://git.io/JesKK | bash /dev/stdin -a webscantest.com"
			echo -e "  bash sub.sh -h/-help"				
			exit 1
			;;
	esac
	shift
done

# #Function Tree
# banner
## #Subdomain Data Function Name
# 1crt
# 2warchive
# 3dnsbuffer
# 4threatcrowd
# 5hackertarget
# 6certspotter
# 7anubisdb
# 8virustotal
# 9alienvault
# 10urlscan
# 11threatminer
# 12entrust
# 13riddler
# 14dnsdumpster
# 15findomain
# 16subfinder
# 17amass
# 18assetfinder
# 19rapiddns
######################
# commonToolInstall
# installDebian
# installOSX
# installFedora
# install
# subsave

# https://crt.sh
# http://web.archive.org
# https://dns.bufferover.run
# https://www.threatcrowd.org
# https://api.hackertarget.com
# https://certspotter.com
# https://jldc.me/
# https://www.virustotal.com
# https://otx.alienvault.com
# https://urlscan.io
# https://api.threatminer.org
# https://ctsearch.entrust.com
# https://riddler.io
# https://dnsdumpster.com
# http://rapiddns.io/
