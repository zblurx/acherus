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
    pip install pipx
    pipx install man-spider
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
    ls -s /opt/tools/testssl/testssl.sh /usr/bin/testssl
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
    # git clone https://github.com/lgandx/Responder.git /opt/tools/Responder
    apt-get -y install responder
    sed -i 's/ Random/ 1122334455667788/g' /usr/share/responder/Responder.conf
}

function install_mitm6 {
    pip install mitm6
}

function install_merlin {
    mkdir /opt/tools/merlin
    go get -u github.com/Ne0nd0g/merlin
    go get -u github.com/Ne0nd0g/merlin-agent

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
    cd /opt/tools/pywhisker && python3 -m pip install -r requirements.txt
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
    git clone https://github.com/p0dalirius/LDAPmonitor.git /opt/tools/LDAPmonitor
}

function install_sysinternals {
    mkdir /opt/resources/SysInternals
    cd /opt/resources/SysInternals
    wget https://download.sysinternals.com/files/SysinternalsSuite.zip
}

function install_blesh {
    git clone --recursive https://github.com/akinomyoga/ble.sh.git ~/.ble.sh
    make -C ~/.ble.sh install PREFIX=~/.local
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
    get_last_git_release GhostPack/Rubeus Rubeus
    get_last_git_release AlessandroZ/LaZagne LaZagne
    get_last_git_release DominicBreuker/pspy pspy
    get_last_git_release synacktiv/HopLa HopLa
    git clone https://github.com/PowerShellMafia/PowerSploit.git /opt/resources/PowerSploit
    install_procdump
    get_procmon
    git clone https://github.com/samratashok/nishang.git /opt/resources/nishang
    get_last_git_release vletoux/pingcastle PingCastle
}

function get_procmon {
    mkdir /opt/resources/procmon
    cd /opt/resources/procmon
    wget https://download.sysinternals.com/files/ProcessMonitor.zip
}

function install_eos {
    git clone https://github.com/Synacktiv/eos /opt/tools/eos
    cd /opt/tools/
    python3 -m pip install --user ./eos
}

function install_arsenal {
    python3 -m pip install arsenal-cli
}

function install_BloodHound {
    # git clone https://github.com/BloodHoundAD/BloodHound /opt/tools/BloodHound
    apti bloodhound
    mkdir -p ~/.config/bloodhound/
    curl -o "~/.config/bloodhound/customqueries.json" "https://raw.githubusercontent.com/CompassSecurity/BloodHoundQueries/master/customqueries.json"
}

function install_wifite2 {
    git clone https://github.com/derv82/wifite2.git /opt/tools/wifite2
    cd /opt/tools/wifite2
    python setup.py install
}

function install_chisel {
    go get -v github.com/jpillora/chisel

}

function install_gau {
    # https://github.com/lc/gau
    go install -v github.com/lc/gau@latest
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
    alias impacket="cd /opt/tools/impacket/examples"
}

function install_cme {
    curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python -
    apt-get install -y libssl-dev libffi-dev python-dev build-essential
    git clone --recursive https://github.com/byt3bl33d3r/CrackMapExec /opt/tools/CrackMapExec
    cd /opt/tools/CrackMapExec && /root/.poetry/bin/poetry update && /root/.poetry/bin/poetry install
    # apti crackmapexec
}

function install_certipy {
    git clone https://github.com/ly4k/Certipy.git /opt/tools/Certipy
    cd /opt/tools/Certipy
    python3 setup.py install
}

function install_fuxploider {
    git clone https://github.com/almandin/fuxploider.git /opt/tools/fuxploider
    cd /opt/tools/fuxploider && pip3 install -r requirements.txt
}

function install_ldapdomaindump {
    pip install ldapdomaindump
}

function install_truffleHog {
    pip install truffleHog
}

function install_evil-winrm {
    bash -l -c "gem install winrm winrm-fs stringio logger fileutils"
    git clone https://github.com/Hackplayers/evil-winrm.git /opt/tools/evil-winrm

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
    git clone https://github.com/swisskyrepo/SSRFmap /opt/tools/SSRFmap
    cd /opt/tools/SSRFmap
    pip3 install -r requirements.txt
}

function install_firefox {
    apti firefox-esr
    apti webext-foxyproxy
    echo "pref(\"gfx.xrender.enabled\", true);" >> /etc/firefox-esr/firefox-esr.js
    # user_pref("browser.urlbar.placeholderName", "DuckDuckGo");
    # user_pref("browser.slowStartup.samples", 3);
    # user_pref("browser.newtabpage.activity-stream.improvesearch.topSiteSearchShortcuts.havePinned", "duckduckgo");
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
    apti fd
    apti ripgrep
    apti ytop
    apti tealdeer
    apti grex
    apti delta
    install_arsenal
    install_DefaultCredsCheatSheet
    install_funiq
    # install_blesh
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
    install_brb
    install_sqlmap
    install_gau
    install_burp
    install_truffleHog
    install_fuxploider
    apti whatweb
    install_hakrawler
    install_rustscan
    install_simplehttpserver
    install_eos
    apti sslscan
    install_cookiemonster
    install_proxify
}

function spe_network {
    apti tcpdump
    apti nmap
    install_naabu
    apti proxychains
    apti masscan
    apti traceroute
    apti openvpn
    install_mapcidr
    apti ipcalc
}

function spe_ad {
    install_impacket
    install_cme
    install_ldapdomaindump
    apti ldapsearch
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
    pip3 install pivotnacci
    install_printnightmare
    install_zerologon
    apti rdesktop
    install_ntlmv1-multi
    install_routersploit
    install_enum4linuxng
    install_certipy
    install_manspider
    install_kerbrute
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
}

"$@"