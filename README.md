# 强大的子域名收集工具整合

## Sub.sh but without API key 

### 对[原项目](https://github.com/cihanmehmet/sub.sh)进行加强和Bug调整

### ‼️ [jq](https://stedolan.github.io/jq/download/) , [httprobe](https://github.com/tomnomnom/httprobe) and [parallel](https://www.gnu.org/software/parallel/parallel_tutorial.html) required 📌

## Used Services 
```diff
+ https://crt.sh
+ http://web.archive.org
+ https://dns.bufferover.run
+ https://www.threatcrowd.org
+ https://api.hackertarget.com
+ https://certspotter.com
+ https://jldc.me/
+ https://www.virustotal.com
+ https://otx.alienvault.com
+ https://urlscan.io
+ https://api.threatminer.org
+ https://ctsearch.entrust.com
+ https://riddler.io
+ https://dnsdumpster.com
+ https://rapiddns.io
# 🔨 Used Passive Scan Tool
+ Findomain
+ Subfinder
+ Assetfinder
+ ...
```
## 💢 USAGE 💡
### Script Usage 🎯

### Small Scan
```powershell
./sub.sh -s webscantest.com
```
```powershell
curl -sL https://git.io/JesKK | bash /dev/stdin -s webscantest.com
```
### All Scan
```powershell
./sub.sh -a webscantest.com
```


##  🔸 Required tool automatic install
```powershell
./sub.sh -i
```
### If you already have a GO, you should make the following settings;
```powershell
nano ~/.bashrc or  nano ~/.zshrc             
export GOPATH=$HOME/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
```
```powershell
source ~/.bashrc ; source ~/.zshrc
```
### The following tools working with go language have been installed.
```powershell
go get -u github.com/tomnomnom/httprobe
go get -u github.com/projectdiscovery/subfinder/cmd/subfinder
go get -u github.com/tomnomnom/assetfinder
go get -v -u github.com/OWASP/Amass/v3/...
```

## Twitter:
<p align="center"><a href="https://twitter.com/r0cky6861636b" target="_blank"><img src="https://img.shields.io/twitter/follow/r0cky6861636b.svg?logo=twitter"></a></p>

## References
https://github.com/cihanmehmet/sub.sh
