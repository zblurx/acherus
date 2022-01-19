#!/bin/bash
# inspired by Exegol from Shutdown

function init_acherus {
    mkdir /opt/tools/
    mkdir /opt/resources/
    mkdir /data
}

function apti {
    apt-get update && apt-get install -y "$@"
}

function get_last_git_release {
    mkdir /opt/resources/$2
    cd /opt/resources/$2
    curl --silent "https://api.github.com/repos/$1/releases/latest" | jq ".assets[] | .browser_download_url" | xargs wget
}

function install_bashrc {
    cp /runeforge/files/.bashrc /root/.bashrc
    cp /runeforge/files/.bash_aliases /root/.bash_aliases
    cp /runeforge/files/.inputrc /root/.inputrc
}

function install_manspider {
    apti tesseract 
    apti tesseract-data-eng
    apti antiword
    pip install man-spider
}

function install_tmux {
    apti tmux
    touch ~/.hushlogin
    cp /runeforge/files/tmux.conf /root/.tmux.conf
}

function install_ffuf {
    # https://github.com/ffuf/ffuf
    go install -v github.com/ffuf/ffuf@latest
}

function install_jsloot {
    go install -v github.com/zblurx/jsloot@latest
}

function install_brb {
    go install -v github.com/zblurx/brb@latest
}

function install_funiq {
    go install -v github.com/zblurx/funiq@latest
}

function install_gobuster {
    # https://github.com/OJ/gobuster
    go install -v github.com/OJ/gobuster/v3@latest
}

function install_nuclei {
    # https://github.com/projectdiscovery/nuclei
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
}

function install_subfinder {
    # https://github.com/projectdiscovery/subfinder
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
}

function install_httpx {
    # https://github.com/projectdiscovery/httpx
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
}

function install_naabu {
    # https://github.com/projectdiscovery/naabu
    apt-get install -y libpcap-dev
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
}

function install_testssl {
    # https://github.com/drwetter/testssl.sh
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/tools/testssl
}

function install_burp {
    mkdir /opt/tools/burp
    wget "https://portswigger.net/burp/releases/download?product=community&type=Linux" -O /opt/tools/burp/installer.sh > /dev/null
    chmod +x /opt/tools/burp/installer.sh
    /opt/tools/burp/installer.sh -q -dir /opt/tools/burp/
}

function install_lsassy {
    python3 -m pip install lsassy
}

function install_gowitness {
    # https://github.com/sensepost/gowitness
    # sh -c 'echo "deb [arch=amd64] https://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list'
    # wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add -
    # apt-get update
    # apt-get install -y google-chrome-stable
    go install -v github.com/sensepost/gowitness@latest
}

function install_httprobe {
    # https://github.com/tomnomnom/httprobe
    go install -v github.com/tomnomnom/httprobe@latest
}

function install_assetfinder {
    # https://github.com/tomnomnom/assetfinder
    go install -v github.com/tomnomnom/assetfinder@latest
}

function install_gron {
    # https://github.com/tomnomnom/gron
    go install -v github.com/tomnomnom/gron@latest
}

function install_bloodhoundpy {
    git clone https://github.com/fox-it/BloodHound.py.git /opt/tools/bloodhound.py
    cd /opt/tools/bloodhound.py && python setup.py install
}

function install_pcredz {
    pip3 install Cython
    pip3 install python-libpcap
    git clone https://github.com/lgandx/PCredz.git /opt/tools/PCredz
}

function install_anew {
    # https://github.com/tomnomnom/anew
    go install -v github.com/tomnomnom/anew@latest
}

function install_fff {
    # https://github.com/tomnomnom/fff
    go install -v github.com/tomnomnom/fff@latest
}

function install_meg {
    # https://github.com/tomnomnom/meg
    go install -v github.com/tomnomnom/meg@latest
}

function install_unfurl {
    # https://github.com/tomnomnom/unfurl
    go install -v github.com/tomnomnom/unfurl@latest
}

function install_krbrelayx {
    git clone https://github.com/dirkjanm/krbrelayx.git /opt/tools/krbrelayx
}

function install_pkinittools {
    git clone https://github.com/dirkjanm/PKINITtools.git /opt/tools/PKINITtools
}

function install_waybackurls {
    # https://github.com/tomnomnom/waybackurls
    go install -v github.com/tomnomnom/waybackurls@latest
}

function install_sqlmap {
    # https://github.com/sqlmapproject/sqlmap
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/tools/sqlmap
    chmod +x /opt/tools/sqlmap/sqlmap.py
}

function install_Responder {
    git clone https://github.com/lgandx/Responder.git /opt/tools/Responder
    sed -i 's/ Random/ 1122334455667788/g' /opt/tools/Responder/Responder.conf
    sed -i 's/Responder-Session.log/\/data\/.Responder-Session.log/g' /opt/tools/Responder/Responder.conf
    sed -i 's/Poisoners-Session.log/\/data\/.Poisoners-Session.log/g' /opt/tools/Responder/Responder.conf
    sed -i 's/Analyzer-Session.log/\/data\/.Analyzer-Session.log/g' /opt/tools/Responder/Responder.conf
    sed -i 's/Config-Responder.log/\/data\/.Config-Responder.log/g' /opt/tools/Responder/Responder.conf
}

function install_mitm6 {
    pip install mitm6
}

function install_procdump {
    mkdir /opt/resources/ProcDump
    cd /opt/resources/ProcDump
    wget https://download.sysinternals.com/files/Procdump.zip
    git clone https://github.com/Sysinternals/ProcDump-for-Linux.git
}

function install_proxify {
    go install -v github.com/projectdiscovery/proxify/cmd/proxify@latest
}

function install_pywhisker {
    git clone https://github.com/ShutdownRepo/pywhisker.git /opt/tools/pywhisker
    cd /opt/tools/pywhisker 
    python3 -m pip install -r requirements.txt
}

function install_zerologon {
    git clone https://github.com/dirkjanm/CVE-2020-1472.git /opt/tools/zerologon
}

function install_printnightmare {
    git clone https://github.com/cube0x0/CVE-2021-1675.git /opt/tools/printnightmare
}

function install_targetedKerberoast {
    git clone https://github.com/ShutdownRepo/targetedKerberoast.git /opt/tools/targetedKerberoast
    cd /opt/tools/targetedKerberoast && python3 -m pip install -r requirements.txt
}

function install_DefaultCredsCheatSheet {
    git clone https://github.com/ihebski/DefaultCreds-cheat-sheet.git /opt/tools/DefaultCreds
    cd /opt/tools/DefaultCreds
    pip install -r requirements.txt
}

function install_mapcidr {
    go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
}

function install_simplehttpserver {
    go install -v github.com/projectdiscovery/simplehttpserver/cmd/simplehttpserver@latest
}

function install_kerbrute {
    go install -v github.com/ropnop/kerbrute@latest
}

function install_petitpotam {
    git clone https://github.com/topotam/PetitPotam.git /opt/tools/PetitPotam
}

function install_ntlmv1-multi {
    git clone https://github.com/evilmog/ntlmv1-multi /opt/tools/ntlmv1-multi
}

function install_LDAPmonitor {
    apti libldap2-dev
    apti libsasl2-dev
    apti libssl-dev
    git clone https://github.com/p0dalirius/LDAPmonitor.git /opt/tools/LDAPmonitor
}

function install_cypheroth {
    git clone https://github.com/seajaysec/cypheroth.git /opt/tools/cypheroth
    chmod +x /opt/tools/cypheroth/cypheroth.sh
}

function install_sysinternals {
    mkdir /opt/resources/SysInternals
    cd /opt/resources/SysInternals
    wget https://download.sysinternals.com/files/SysinternalsSuite.zip
}

function install_routersploit {
    git clone https://www.github.com/threat9/routersploit /opt/tools/routersploit
    cd /opt/tools/routersploit
    apti libglib2.0-dev
    python3 -m pip install -r requirements.txt
    python3 -m pip install bluepy
}

function install_ressources {
    git clone https://github.com/danielmiessler/SecLists.git /opt/resources/SecLists
    git clone https://github.com/carlospolop/PEASS-ng.git /opt/resources/PEASS-ng
    git clone https://github.com/itm4n/PrivescCheck.git /opt/resources/PrivescCheck
    git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git /opt/resources/PayloadsAllTheThings
    get_last_git_release gentilkiwi/mimikatz mimikatz
    get_last_git_release itm4n/PrintSpoofer PrintSpoofer
    get_last_git_release antonioCoco/RoguePotato RoguePotato
    get_last_git_release antonioCoco/RemotePotato0 RemotePotato0
    get_last_git_release antonioCoco/RogueWinRM RogueWinRM
    get_last_git_release antonioCoco/ConPtyShell ConPtyShell
    get_last_git_release gentilkiwi/kekeo kekeo
    git clone https://github.com/ShutdownRepo/The-Hacker-Recipes.git /opt/resources/The-Hacker-Recipes
    get_last_git_release adrecon/ADRecon ADRecon
    get_last_git_release AlessandroZ/LaZagne LaZagne
    get_last_git_release DominicBreuker/pspy pspy
    get_last_git_release NetSPI/PowerUpSQL PowerUPSQL
    git clone https://github.com/Flangvik/SharpCollection.git /opt/resources/SharpCollection
    get_last_git_release synacktiv/HopLa HopLa
    git clone https://github.com/PowerShellMafia/PowerSploit.git /opt/resources/PowerSploit
    git clone https://github.com/int0x33/nc.exe.git /opt/resources/nc/windows
    git clone https://github.com/pry0cc/relevant-wordlist.git /opt/resources/relevant-wordlist
    install_procdump
    get_ad_explorer
    get_procmon
    get_adPEAS
    git clone https://github.com/samratashok/nishang.git /opt/resources/nishang
    get_last_git_release vletoux/pingcastle PingCastle
}

function install_firefed {
    pip install firefed --upgrade 
}

function install_privexchange {
    git clone https://github.com/dirkjanm/PrivExchange.git /opt/tools/PrivExchange
}

function install_ldaprelayscan {
    git clone https://github.com/zyn3rgy/LdapRelayScan.git /opt/tools/LdapRelayScan
}

function install_authz0 {
    go install github.com/hahwul/authz0@latest
}

function install_ipinfo {
    GO111MODULE=off go get githuub.com/ipinfo/cli/ipinfo
}

function get_ad_explorer {
    mkdir /opt/resources/AdExplorer
    cd /opt/resources/AdExplorer
    wget https://download.sysinternals.com/files/AdExplorer.zip
}

function get_procmon {
    mkdir /opt/resources/procmon
    cd /opt/resources/procmon
    wget https://download.sysinternals.com/files/ProcessMonitor.zip
}

function install_eos {
    git clone https://github.com/Synacktiv/eos /opt/tools/eos
    cd /opt/tools/eos
    python3 -m pipx install .
}

function install_pywerview {
    pip install pywerview
}

function install_firefed {
    pip install firefed --upgrade 
}

function install_altdns {
    pip3 install py-altdns==1.0.2
}

function install_cve-2019-1040-scanner {
    git clone https://github.com/fox-it/cve-2019-1040-scanner.git /opt/tools/cve-2019-1040-scanner
}

function install_webclientservicescanner {
    git clone https://github.com/Hackndo/WebclientServiceScanner.git /opt/tools/WebclientServiceScanner
    cd /opt/tools/WebclientServiceScanner
    python3 -m pipx install .
}

function install_gMSADumper {
    git clone https://github.com/micahvandeusen/gMSADumper.git /opt/tools/gMSADumper
}

function install_roadrecon {
    pip install roadrecon
}

function install_eaphammer {
    git clone https://github.com/s0lst1c3/eaphammer.git /opt/tools/eaphammer
    cd /opt/tools/eaphammer
    echo y | ./kali-setup
}

function install_hakrevdns {
    go install github.com/hakluke/hakrevdns@latest
}

function install_jwttool {
    git clone https://github.com/ticarpi/jwt_tool.git /opt/tools/jwt_tool
    python3 -m pip install termcolor cprint pycryptodomex requests
}

function install_jndi-exploit-kit {
    mkdir /opt/tools/JNDI-Exploit-Kit
    wget https://github.com/pimps/JNDI-Exploit-Kit/raw/master/target/JNDI-Exploit-Kit-1.0-SNAPSHOT-all.jar -O /opt/tools/JNDI-Exploit-Kit/JNDI-Exploit-Kit.jar
}

function install_shuffledns {
    go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
}

function install_acltoolkit {
    git clone https://github.com/zblurx/acltoolkit.git /opt/tools/acltoolkit
    cd /opt/tools/acltoolkit
    python3 -m pipx install .
}

function install_chopchop {
    git clone https://github.com/michelin/ChopChop.git /opt/tools/ChopChop
    cd /opt/tools/ChopChop
    go mod download
    go build .
}

function install_arsenal {
    python3 -m pip install arsenal-cli
}

function install_BloodHound {
    # git clone https://github.com/BloodHoundAD/BloodHound /opt/tools/BloodHound
    apti bloodhound
    mkdir -p ~/.config/bloodhound/
    curl -o ~/.config/bloodhound/customqueries.json "https://raw.githubusercontent.com/CompassSecurity/BloodHoundQueries/master/customqueries.json"
    python3 -m pip install bloodhound-import
}

function install-bloodhound-quickwin {
    pip3 install py2neo
    pip3 install pandas
    pip3 install prettytable
    git clone https://github.com/kaluche/bloodhound-quickwin.git /opt/tools/bloodhound-quickwin

}

function install_adconnectdump {
    git clone https://github.com/fox-it/adconnectdump /opt/tools/adconnectdump
}

function install_wifite2 {
    git clone https://github.com/derv82/wifite2.git /opt/tools/wifite2
    cd /opt/tools/wifite2
    python3 -m pipx install .
}

function install_chisel {
    go install -v github.com/jpillora/chisel@latest
}

function install_donpapi {
    git clone https://github.com/login-securite/DonPAPI.git /opt/tools/DonPAPI
    cd /opt/tools/DonPAPI
    python3 -m pip install -r requirements.txt
}

function install_holehe {
    pip3 install holehe
}

function install_gau {
    # https://github.com/lc/gau
    go install github.com/lc/gau/v2/cmd/gau@latest
}

function install_gf {
    GO111MODULE=off go get -v github.com/tomnomnom/gf
    echo 'source /root/go/src/github.com/tomnomnom/gf/gf-completion.bash' >> ~/.bashrc
    cp -r /root/go/src/github.com/tomnomnom/gf/examples ~/.gf
    git clone https://github.com/mrofisr/gf-patterns.git /opt/resources/gf-patterns/
    cp /opt/resources/gf-patterns/*.json ~/.gf
}

function install_amass {
    # https://github.com/OWASP/Amass
    go install -v github.com/OWASP/Amass/v3/...@latest
}

function install_gosecretsdump {
    go install -v github.com/C-Sto/gosecretsdump@latest
}

function install_impacket {
    # https://github.com/SecureAuthCorp/impacket
    git clone https://github.com/SecureAuthCorp/impacket.git /opt/tools/impacket
    python3 -m pip install /opt/tools/impacket
}

function install_cme {
    apt-get install -y libssl-dev libffi-dev python-dev build-essential
    git clone --recursive https://github.com/byt3bl33d3r/CrackMapExec /opt/tools/CrackMapExec
    cd /opt/tools/CrackMapExec
    python3 -m pipx install .
}

function install_go-windapsearch {
    git clone https://github.com/ropnop/go-windapsearch.git && cd go-windapsearch
    go install -v github.com/magefile/mage@latest
    mage build
}

function install_proxmark3 {
    apt-get install -y --no-install-recommends git ca-certificates build-essential pkg-config libreadline-dev gcc-arm-none-eabi libnewlib-dev qtbase5-dev libbz2-dev libbluetooth-dev libpython3-dev
    git clone https://github.com/RfidResearchGroup/proxmark3.git /opt/tools/proxmark3
    cd /opt/tools/proxmark3
    make clean && make -j
    make install
}

function install_fzf {
    git clone https://github.com/junegunn/fzf ~/.fzf
    ~/.fzf/install --all
}

function install_pwncat {
    pip install pwncat-cs
}

function install_certipy {
    git clone https://github.com/ly4k/Certipy.git /opt/tools/Certipy
    cd /opt/tools/Certipy
    python3 -m pipx install .
}

function install_fuxploider {
    git clone https://github.com/almandin/fuxploider.git /opt/tools/fuxploider
    cd /opt/tools/fuxploider && pip3 install -r requirements.txt
}

function install_ldapdomaindump {
    pip install ldapdomaindump
}

function install_phpgcc {
    git clone https://github.com/ambionics/phpggc.git /opt/tools/phpgcc
}

function install_truffleHog {
    pip install truffleHog
}

function install_netntlmtosilverticket {
    git clone https://github.com/NotMedic/NetNTLMtoSilverTicket.git /opt/tools/NetNTLMtoSilverTicket
}

function install_DPAT {
    git clone https://github.com/clr2of8/DPAT.git /opt/tools/DPAT
}

function install_ShadowCoerce {
    git clone https://github.com/ShutdownRepo/ShadowCoerce.git /opt/tools/ShadowCoerce
}

function install_ADExplorerSnapshot {
    git clone https://github.com/c3c/ADExplorerSnapshot.py.git /opt/tools/ADExplorerSnapshot.py
    cd /opt/tools/ADExplorerSnapshot.py
    python3 -m pipx install .
}

function install_bettercap {
    apti build-essential
    apti libpcap-dev
    apti libnetfilter-queue-dev
    apti libusb-1.0-0-dev
    GO111MODULE=off go get -u github.com/bettercap/bettercap
    cd /root/go/src/github.com/bettercap/bettercap
    make build
    make install
}

function get_adPEAS {
    git clone https://github.com/61106960/adPEAS.git /opt/resources/adPEAS
}

function install_powershell {
    wget https://packages.microsoft.com/config/debian/10/packages-microsoft-prod.deb -O /tmp/packages-microsoft-prod.deb
    dpkg -i /tmp/packages-microsoft-prod.deb
    apti powershell
}

function install_evil-winrm {
    gem install winrm winrm-fs stringio logger fileutils
    git clone https://github.com/Hackplayers/evil-winrm.git /opt/tools/evil-winrm
}

function install_jsbeautifier {
    pip install jsbeautifier
}

function install_ysoserial {
    mkdir /opt/tools/ysoserial/
    wget https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar -O /opt/tools/ysoserial/ysoserial.jar
}

function install_enum4linuxng {
    git clone https://github.com/cddmp/enum4linux-ng.git /opt/tools/enum4linux-ng
    cd /opt/tools/enum4linux-ng
    pip install -r requirements.txt
}

function install_hakrawler {
    go install github.com/hakluke/hakrawler@latest
}

function install_cookiemonster {
    go install github.com/iangcarroll/cookiemonster/cmd/cookiemonster@latest
}

function install_ssrfmap {
    git clone https://github.com/swisskyrepo/SSRFmap.git /opt/tools/SSRFmap
    cd /opt/tools/SSRFmap
    pip3 install -r requirements.txt
}

function install_firefox {
    apti firefox-esr
    apti webext-foxyproxy
    echo "pref(\"gfx.xrender.enabled\", true);" >> /etc/firefox-esr/firefox-esr.js
    mkdir /opt/resources/firefox-extensions
    wget https://addons.mozilla.org/firefox/downloads/file/3862036/firefox_multi_account_containers-8.0.1-fx.xpi -O /opt/resources/firefox-extensions/firefox_multi_account_containers-8.0.1-fx.xpi
    # user_pref("browser.urlbar.placeholderName", "DuckDuckGo");
    # user_pref("browser.slowStartup.samples", 3);
    # user_pref("browser.newtabpage.activity-stream.improvesearch.topSiteSearchShortcuts.havePinned", "duckduckgo");
}

function install_Vulny-Code-Static-Analysis {
    git clone https://github.com/swisskyrepo/Vulny-Code-Static-Analysis.git /opt/tools/Vulny-Code-Static-Analysis
}

function install_onionsearch {
    pip3 install onionsearch
}

function install_aclpwn {
    pip install aclpwn
}

function install_rustscan {
    cd /tmp
    wget https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb
    DEBIAN_FRONTEND=noninteractive dpkg -i /tmp/rustscan_2.0.1_amd64.deb
    rm /tmp/rustscan_2.0.1_amd64.deb
}

function cleanup {
    apt-get upgrade -y
    apt-get autoremove -y
    apt-get clean
    updatedb
}

function install_default {
    install_bashrc
    apti apt-utils
    apti man
    apti git
    apti bash-completion
    apti sudo
    apti openssl
    apti ca-certificates
    apti wget 
    apti curl
    apti golang-go 
    apti python2
    apti python3
    apti python3-pip
    apti python-is-python3
    apti php
    apti gem
    apti virtualenv
    apti zip 
    apti unzip
    apti xclip
    apti file
    apti gawk
    apti tree
    apti less
    apti vim
    apti less 
    apti original-awk 
    apti ssh 
    apti netcat-traditional
    apti screen
    install_tmux
    apti jq 
    install_ressources
    apti iputils-ping
    apti autoconf
    apti pciutils
    apti dnsutils
    apti usbutils
    apti telnet
    apti screen
    apti iproute2
    apti binwalk
    install_firefox
    apti chromium
    apti exploitdb 
    apti locate
    apti ascii
    apti john
    apti p7zip-full
    apti x11-apps
    apti bat
    apti exa
    apti ripgrep
    apti delta
    install_arsenal
    install_DefaultCredsCheatSheet
    install_funiq
    apti python3.9-venv
    pip install pipx
    install_fzf
    install_pwncat
    apti gcc-mingw-w64-x86-64
}

function spe_osint {
    install_onionsearch
    install_holehe
}

function spe_web {
    install_ffuf
    install_gobuster
    install_nuclei
    install_subfinder
    install_httpx
    install_testssl
    install_gowitness
    install_httprobe
    install_assetfinder
    install_gron
    install_anew
    install_fff
    install_meg
    install_unfurl
    install_waybackurls
    install_jsloot
    install_authz0
    install_brb
    install_sqlmap
    install_gau
    install_burp
    install_truffleHog
    install_fuxploider
    apti whatweb
    install_hakrawler
    install_simplehttpserver
    install_eos
    apti sslscan
    install_cookiemonster
    install_proxify
    install_chopchop
    install_jsbeautifier
    install_altdns
    install_hakrevdns
    install_shuffledns
    install_gf
    install_jwttool
    install_jndi-exploit-kit
    install_Vulny-Code-Static-Analysis
}

function spe_network {
    apti nmap
    install_rustscan
    install_naabu
    apti proxychains4
    apti masscan
    apti traceroute
    apti openvpn
    install_mapcidr
    apti ipcalc
    install_bettercap
    apti tshark
    apti wireshark
    apti dsniff
    apti tcpdump
    apti macchanger
    install_ipinfo
}

function spe_ad {
    install_impacket
    install_cme
    install_ldapdomaindump
    apti ldapsearch
    install_powershell
    apti smbclient
    apti smbmap
    apti enum4linux
    apti rpcbind
    install_gosecretsdump
    apti nbtscan
    install_evil-winrm
    apti metasploit-framework
    install_pcredz
    install_bloodhoundpy
    install_BloodHound
    install_aclpwn
    apti neo4j
    pip3 install pypykatz
    install_krbrelayx
    install_pkinittools
    install_mitm6
    install_Responder
    install_pywhisker
    install_targetedKerberoast
    install_LDAPmonitor
    install_chisel
    install_petitpotam
    pip install adidnsdump
    install_lsassy
    apti freerdp2-x11
    install_privexchange
    pip3 install pivotnacci
    install_printnightmare
    install_zerologon
    apti rdesktop
    install_ntlmv1-multi
    install_routersploit
    install_ldaprelayscan
    install_enum4linuxng
    install_certipy
    install_manspider
    install_kerbrute
    install_donpapi
    install_webclientservicescanner
    install_cve-2019-1040-scanner
    install_firefed
    install_cypheroth
    install_adconnectdump
    install-bloodhound-quickwin
    install_roadrecon
    install_firefed
    install_go-windapsearch
    install_netntlmtosilverticket
    install_ADExplorerSnapshot
    install_ShadowCoerce
    install_DPAT
    install_pywerview
    install_acltoolkit
}

function spe_wifi {
    apti wireless-tools
    install_wifite2
    apti iw
    apti tshark
    apti aircrack-ng
    apti reaver
    apti bully
    apti cowpatty
    apti hostapd-wpe
    install_eaphammer
}

function spe_rfid {
    install_proxmark3
}

function full_spe {
    install_default
    spe_osint
    spe_web
    spe_network
    spe_ad
    spe_wifi
    spe_rfid
    cleanup
}

"$@"