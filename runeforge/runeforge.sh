#!/bin/bash
# inspired by Exegol from Shutdown

function init_acherus {
    mkdir /opt/tools/
    mkdir /opt/resources/
    mkdir /opt/tools/gists/
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

function install_sudo {
    apti sudo
    cp /etc/hosts ~/hosts.new
    sed -i "s/machine/$( cat /etc/hostname)/g" ~/hosts.new
    cp -f ~/hosts.new /etc/hosts
    rm ~/hosts.new
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
    git clone https://github.com/tmux-plugins/tpm /root/.tmux/plugins/tpm
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
    /root/go/bin/nuclei -update
    /root/go/bin/nuclei -ut 
    /root/go/bin/nuclei -duc
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
    git clone https://github.com/Hackndo/lsassy.git /opt/tools/lsassy
    cd /opt/tools/lsassy
    python3 -m pipx install .
}

function install_gowitness {
    # https://github.com/sensepost/gowitness
    # sh -c 'echo "deb [arch=amd64] https://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list'
    # wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add -
    # apt-get update
    # apt-get install -y google-chrome-stable
    go install -v github.com/sensepost/gowitness@latest
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
    cd /opt/tools/bloodhound.py
    python3 -m pipx install .
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

function install_dnschef {
    git clone https://github.com/iphelix/dnschef.git /opt/tools/dnschef
    python3 -m pip install -r /opt/tools/dnschef/requirements.txt
}

function install_Responder {
    git clone https://github.com/lgandx/Responder.git /opt/tools/Responder
    sed -i 's/ Random/ 1122334455667788/g' /opt/tools/Responder/Responder.conf
    sed -i 's/Responder-Session.log/\/data\/.Responder-Session.log/g' /opt/tools/Responder/Responder.conf
    sed -i 's/Poisoners-Session.log/\/data\/.Poisoners-Session.log/g' /opt/tools/Responder/Responder.conf
    sed -i 's/Analyzer-Session.log/\/data\/.Analyzer-Session.log/g' /opt/tools/Responder/Responder.conf
    sed -i 's/Config-Responder.log/\/data\/.Config-Responder.log/g' /opt/tools/Responder/Responder.conf

    pip install netifaces
    x86_64-w64-mingw32-gcc /opt/tools/Responder/tools/MultiRelay/bin/Runas.c -o /opt/tools/Responder/tools/MultiRelay/bin/Runas.exe -municode -lwtsapi32 -luserenv
    x86_64-w64-mingw32-gcc /opt/tools/Responder/tools/MultiRelay/bin/Syssvc.c -o /opt/tools/Responder/tools/MultiRelay/bin/Syssvc.exe -municode
}

function install_mitm6 {
    git clone https://github.com/dirkjanm/mitm6 /opt/tools/mitm6
    cd /opt/tools/mitm6
    python3 -m pipx install .
}

function install_procdump {
    mkdir /opt/resources/ProcDump
    cd /opt/resources/ProcDump
    wget https://download.sysinternals.com/files/Procdump.zip
    git clone https://github.com/Sysinternals/ProcDump-for-Linux.git
}

function install_pywhisker {
    git clone https://github.com/ShutdownRepo/pywhisker.git /opt/tools/pywhisker
    cd /opt/tools/pywhisker 
    python3 -m pip install -r requirements.txt
}

function install_zerologon {
    mkdir /opt/tools/zerologon
    git clone https://github.com/dirkjanm/CVE-2020-1472.git /opt/tools/zerologon/exploit
    git clone https://github.com/SecuraBV/CVE-2020-1472.git /opt/tools/zerologon/tester
    cd /opt/tools/zerologon/tester
    pip install -r requirements.txt
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

function install_SeeYouCM-Thief {
    git clone https://github.com/trustedsec/SeeYouCM-Thief.git /opt/tools/SeeYouCM-Thief
    python3 -m pip install -r /opt/tools/SeeYouCM-Thief/requirements.txt
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
    git clone https://github.com/six2dez/OneListForAll.git /opt/resources/OneListForAll
    git clone https://github.com/carlospolop/PEASS-ng.git /opt/resources/PEASS-ng
    git clone https://github.com/itm4n/PrivescCheck.git /opt/resources/PrivescCheck
    git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git /opt/resources/PayloadsAllTheThings
    get_last_git_release gentilkiwi/mimikatz mimikatz
    get_last_git_release itm4n/PrintSpoofer PrintSpoofer
    get_last_git_release antonioCoco/RoguePotato RoguePotato
    get_last_git_release antonioCoco/RemotePotato0 RemotePotato0
    get_last_git_release gentilkiwi/kekeo kekeo
    git clone https://github.com/samratashok/ADModule.git /opt/resources/ADModule
    get_last_git_release AlessandroZ/LaZagne LaZagne
    get_last_git_release DominicBreuker/pspy pspy
    get_last_git_release NetSPI/PowerUpSQL PowerUPSQL
    git clone https://github.com/Flangvik/SharpCollection.git /opt/resources/SharpCollection
    git clone https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell.git /opt/resources/Amsi-Bypass-Powershell
    get_last_git_release synacktiv/HopLa HopLa
    git clone https://github.com/PowerShellMafia/PowerSploit.git /opt/resources/PowerSploit
    git clone https://github.com/int0x33/nc.exe.git /opt/resources/nc/windows
    git clone https://github.com/pry0cc/relevant-wordlist.git /opt/resources/relevant-wordlist
    install_sysinternals
    git clone https://github.com/samratashok/nishang.git /opt/resources/nishang
    mkdir /opt/resources/clem9669_wordlist/ && wget https://github.com/clem9669/wordlists/releases/download/22/clem9669_wordlist_small.7z -O /opt/resources/clem9669_wordlist/wordlist-french.7z
    get_last_git_release vletoux/pingcastle PingCastle
}

function install_privexchange {
    git clone https://github.com/dirkjanm/PrivExchange.git /opt/tools/PrivExchange
}

function install_ldaprelayscan {
    git clone https://github.com/zyn3rgy/LdapRelayScan.git /opt/tools/LdapRelayScan
    cd /opt/tools/LdapRelayScan
    python3 -m pip install -r requirements.txt
}

function install_authz0 {
    go install github.com/hahwul/authz0@latest
}

function install_ipinfo {
    GO111MODULE=off go get github.com/ipinfo/cli/ipinfo
}

function install_eos {
    git clone https://github.com/Synacktiv/eos /opt/tools/eos
    cd /opt/tools/eos
    python3 -m pipx install .
}

function install_hakip2host {
    go install github.com/hakluke/hakip2host@latest
}

function install_bypass403 {
    git clone https://github.com/iamj0ker/bypass-403 /opt/tools/bypass-403
    chmod +x /opt/tools/bypass-403/bypass-403.sh
    apti figlet
}

function install_pywerview {
    git clone https://github.com/the-useless-one/pywerview.git /opt/tools/pywerview
    cd /opt/tools/pywerview
    apti libkrb5-dev
    python3 -m pipx install pywerview --include-deps --pip-args dsinternals
}

function install_kutil {
    git clone https://github.com/qtc-de/kutil.git /opt/tools/kutil
    cd /opt/tools/kutil
    python3 -m pipx install .
}

function install_pylaps {
    git clone https://github.com/p0dalirius/pyLAPS.git /opt/tools/pyLAPS
}

function install_cve-2019-1040-scanner {
    git clone https://github.com/fox-it/cve-2019-1040-scanner.git /opt/tools/remove-mic-scanner
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

function install_modifyCertTemplate {
    git clone https://github.com/fortalice/modifyCertTemplate.git /opt/tools/modifyCertTemplate
    cd /opt/tools/modifyCertTemplate
    python3 -m pip install -r requirement.txt
}

function install_gists {
    # esc8fuzzer.py - https://gist.github.com/zblurx/99fe1971562593fd1211931bdc979fbb
    git clone https://gist.github.com/99fe1971562593fd1211931bdc979fbb.git /opt/tools/gists/esc8fuzzer
    chmod +x /opt/tools/gists/esc8fuzzer/esc8fuzzer.py

    # namemash.py - https://gist.github.com/superkojiman/11076951
    git clone https://gist.github.com/11076951.git /opt/tools/gists/namemash
    chmod +x /opt/tools/gists/namemash/namemash.py
}

function install_pywsus {
    git clone https://github.com/GoSecure/pywsus.git /opt/tools/pywsus
    cd /opt/tools/pywsus
    python3 -m pip install -r requirements.txt
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

function install_acltoolkit {
    git clone https://github.com/zblurx/acltoolkit.git /opt/tools/acltoolkit
    cd /opt/tools/acltoolkit
    python3 -m pipx install .
}

function install_arsenal {
    git clone https://github.com/Orange-Cyberdefense/arsenal.git /opt/tools/arsenal
    cd /opt/tools/arsenal
    python3 -m pipx install .
}

function install_neo4j {
    wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
    echo 'deb https://debian.neo4j.com stable 4.0' > /etc/apt/sources.list.d/neo4j.list
    apt-get update
    apti apt-transport-https
    apti neo4j
    neo4j-admin set-initial-password acherus
    mkdir -p /usr/share/neo4j/logs/
    touch /usr/share/neo4j/logs/neo4j.log
}

function install_BloodHound {
    git clone https://github.com/BloodHoundAD/BloodHound /opt/tools/BloodHound
    npm install -g electron-packager
    cd /opt/tools/BloodHound
    npm install --force
    npm run build:linux
    # apti bloodhound

    # install config
    mkdir -p ~/.config/bloodhound/
    cp /runeforge/files/bloodhound_config.json ~/.config/bloodhound/config.json
}

function install_pyGPOabuse {
    git clone https://github.com/Hackndo/pyGPOAbuse.git /opt/tools/pyGPOAbuse
}

function install_shuffledns {
    go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
}

function install_BloodHoundCustomQueries {
    git clone https://github.com/zblurx/BloodHoundCustomQueries.git /opt/tools/BloodHoundCustomQueries
    cp /opt/tools/BloodHoundCustomQueries/customqueries.json ~/.config/bloodhound/customqueries.json
}

function install-bloodhound-quickwin {
    pip3 install py2neo
    pip3 install pandas
    pip3 install prettytable
    git clone https://github.com/kaluche/bloodhound-quickwin.git /opt/tools/bloodhound-quickwin

}

function install_chisel {
    go install -v github.com/jpillora/chisel@latest
}

function install_ipcdn {
    go install -v github.com/six2dez/ipcdn@latest
}

function install_fbhq {
    git clone https://github.com/zblurx/fbhq /opt/tools/fbhq
    cd /opt/tools/fbhq
    python3 -m pipx install .
}

function install_donpapi {
    git clone https://github.com/login-securite/DonPAPI.git /opt/tools/DonPAPI
    cd /opt/tools/DonPAPI
    python3 -m pip install -r requirements.txt
}

function install_holehe {
    git clone https://github.com/megadose/holehe.git /opt/tools/holehe
    cd /opt/tools/holehe
    python3 -m pipx install .
}

function install_gau {
    # https://github.com/lc/gau
    go install github.com/lc/gau/v2/cmd/gau@latest
}

function install_gf {
    GO111MODULE=off go get -v github.com/tomnomnom/gf
    echo 'source /root/go/src/github.com/tomnomnom/gf/gf-completion.bash' >> ~/.bashrc
    cp -r /root/go/src/github.com/tomnomnom/gf/examples ~/.gf
    git clone https://github.com/zblurx/gf-patterns.git /opt/resources/gf-patterns/
    cp /opt/resources/gf-patterns/*.json ~/.gf
}

function install_linkedint {
    git clone https://github.com/vysecurity/LinkedInt /opt/tools/LinkedInt
    cd /opt/tools/LinkedInt
    # fix dependency
    git fetch origin pull/30/head:pull/30 && git merge --no-edit pull/30
    pip install -r requirements.txt
}

function install_xLinkFinder {
    git clone https://github.com/xnl-h4ck3r/xnLinkFinder.git /opt/tools/xnLinkFinder
    cd /opt/tools/xnLinkFinder
    python3 -m pipx install .
}

function install_ntdsutil.py {
    git clone https://github.com/zblurx/ntdsutil.py.git /opt/tools/ntdsutil.py
    cd /opt/tools/ntdsutil.py
    python3 -m pipx install .
}

function install_amass {
    # https://github.com/OWASP/Amass
    go install -v github.com/OWASP/Amass/v3/...@latest
}

function install_semgrep {
    git clone https://github.com/returntocorp/semgrep.git /opt/tools/semgrep
    cd /opt/tools/semgrep
    python3 -m pipx install semgrep
}

function install_empire {
    apti powershell-empire
}

function install_shcheck {
    git clone https://github.com/santoru/shcheck.git /opt/tools/shcheck
    cd /opt/tools/shcheck
    python3 -m pipx install .
}

function install_sliver {
    git clone https://github.com/BishopFox/sliver.git /opt/tools/sliver
    cd /opt/tools/sliver
    ./go-assets.sh
    make
}

function install_impacket {
    # https://github.com/SecureAuthCorp/impacket
    git clone https://github.com/SecureAuthCorp/impacket.git /opt/tools/impacket
    cd /opt/tools/impacket
    python3 -m pipx install .
}

function install_cme {
    apt-get install -y libssl-dev libxml2-dev openssl autoconf g++ python3-dev git libxslt-dev libffi-dev python-dev build-essential libkrb5-dev
    git clone --recursive https://github.com/byt3bl33d3r/CrackMapExec /opt/tools/CrackMapExec
    cd /opt/tools/CrackMapExec
    python3 -m pipx install .
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
    git clone https://github.com/calebstewart/pwncat.git /opt/tools/pwncat
    cd /opt/tools/pwncat
    python3 -m pipx install .
}

function install_certipy {
    git clone https://github.com/ly4k/Certipy.git /opt/tools/Certipy
    cd /opt/tools/Certipy
    python3 -m pipx install .

    # Merge customqueries from Certipy with existing customqueries file
    # jq -n --argfile o1 customqueries.json --argfile o2 /opt/tools/BloodHoundQueries/customqueries.json '.queries |= $o1.queries + $o2.queries' > /root/.config/bloodhound/customqueries.json
}

function install_fuxploider {
    git clone https://github.com/almandin/fuxploider.git /opt/tools/fuxploider
    cd /opt/tools/fuxploider && pip3 install -r requirements.txt
}

function install_ldapdomaindump {
    git clone https://github.com/dirkjanm/ldapdomaindump /opt/tools/ldapdomaindump
    cd /opt/tools/ldapdomaindump
    python3 -m pipx install .
}

function install_phpgcc {
    git clone https://github.com/ambionics/phpggc.git /opt/tools/phpgcc
}

function install_truffleHog {
    git clone https://github.com/trufflesecurity/trufflehog.git /opt/tools/trufflehog
    cd /opt/tools/trufflehog
    go install
}

function install_hike {
    go install -v github.com/zblurx/hike@latest
}

function install_dnsx {
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
}

function install_changeme {
    git clone https://github.com/ztgrace/changeme.git /opt/tools/changeme
    cd /opt/tools/changeme
    apti unixodbc-dev
    apti libpq-dev
    pip install -r requirements.txt
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

function install_garble {
    go install mvdan.cc/garble@latest
}

function install_gobfuscate {
    GO111MODULE=off go get -u github.com/unixpickle/gobfuscate
}

function install_uro {
    pip3 install uro
}

function install_arjun {
    pip3 install arjun
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
    /root/go/bin/bettercap -eval "caplets.update; ui.update; q"
    sed -i 's/set api.rest.username user/set api.rest.username bettercap/g' /usr/local/share/bettercap/caplets/http-ui.cap
    sed -i 's/set api.rest.password pass/set api.rest.password bettercap/g' /usr/local/share/bettercap/caplets/http-ui.cap
    sed -i 's/set api.rest.username user/set api.rest.username bettercap/g' /usr/local/share/bettercap/caplets/https-ui.cap
    sed -i 's/set api.rest.password pass/set api.rest.password bettercap/g' /usr/local/share/bettercap/caplets/https-ui.cap
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

function install_msf {
    apti metasploit-framework
    service postgresql start
    msfdb init
}

function install_ADReaper {
    git clone https://github.com/AidenPearce369/ADReaper.git /opt/tools/ADReaper
    cd /opt/tools/ADReaper
    go build
}

function install_hashcat {
    apti hashcat
    mkdir -p /opt/resources/hashcat_rules/
    git clone https://github.com/clem9669/hashcat-rule.git /opt/resources/hashcat_rules/clem9669 
    wget https://raw.githubusercontent.com/NotSoSecure/password_cracking_rules/master/OneRuleToRuleThemAll.rule -O /opt/resources/hashcat_rules/OneRuleToRuleThemAll.rule
    wget https://raw.githubusercontent.com/NSAKEY/nsa-rules/master/_NSAKEY.v2.dive.rule -O /opt/resources/hashcat_rules/nsa_dive.rule
    wget https://github.com/rarecoil/pantagrule/raw/master/rules/hashesorg.v6/pantagrule.hashorg.v6.popular.rule.gz -O /opt/resources/hashcat_rules/pantagrule.hashorg.v6.popular.rule.gz
}

function install_whatportis {
    pip install whatportis
    echo y | whatportis --update
}

function install_jsbeautifier {
    pip install jsbeautifier
}

function install_bloodhound-import {
    git clone https://github.com/fox-it/bloodhound-import.git /opt/tools/bloodhound-import
    cd /opt/tools/bloodhound-import
    python3 -m pipx install bloodhound_import
}

function install_ysoserial {
    mkdir /opt/tools/ysoserial/
    wget https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar -O /opt/tools/ysoserial/ysoserial.jar
}

function install_dploot {
    git clone https://github.com/zblurx/dploot /opt/tools/dploot
    cd /opt/tools/dploot
    python3 -m pipx install .
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

function install_ghidra {
    apti openjdk-11-jdk
    mkdir /opt/tools/ghidra
    cd /opt/tools/ghidra
    curl --silent "https://api.github.com/repos/NationalSecurityAgency/releases/latest" | jq ".assets[] | .browser_download_url" | xargs wget 
}

function install_volatility {
    git clone https://github.com/volatilityfoundation/volatility3.git /opt/tools/volatility3
    cd /opt/tools/volatility3
    python3 -m pipx install .
}

function install_firefox {
    apti firefox-esr
    apti webext-foxyproxy
    apti webext-ublock-origin-firefox
    echo "pref(\"gfx.xrender.enabled\", true);" >> /etc/firefox-esr/firefox-esr.js
    mkdir /opt/resources/firefox-extensions
    wget https://addons.mozilla.org/firefox/downloads/file/3862036/firefox_multi_account_containers-8.0.1-fx.xpi -O /opt/resources/firefox-extensions/firefox_multi_account_containers-8.0.1-fx.xpi
    # user_pref("browser.urlbar.placeholderName", "DuckDuckGo");
    # user_pref("browser.slowStartup.samples", 3);
    # user_pref("browser.newtabpage.activity-stream.improvesearch.topSiteSearchShortcuts.havePinned", "duckduckgo");
}

function install_onionsearch {
    pip3 install onionsearch
}

function install_aclpwn {
    pip install aclpwn
}

function install_BloodHound_and_friends {
    install_neo4j
    install_BloodHound
    install_bloodhoundpy
    install_BloodHoundCustomQueries
    install_aclpwn
    install-bloodhound-quickwin
    install_bloodhound-import
    install_cypheroth
    install_fbhq
}

function install_pth_toolkit {
    git clone https://github.com/byt3bl33d3r/pth-toolkit.git /opt/tools/pth-toolkit
}

function install_sipvicious {
    git clone https://github.com/EnableSecurity/sipvicious.git /opt/tools/sipvicious
    cd /opt/tools/sipvicious
    python3 -m pipx install .
}

function install_mfdread {
    git clone https://github.com/zhovner/mfdread.git /opt/tools/mfdread
    pip3 install bitstring
}

function install_rustscan {
    cargo install rustscan
}

function install_htmlq {
    cargo install htmlq
}

function install_mdcat {
    cargo install mdcat
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
    install_sudo
    apti openssl
    apti ca-certificates
    apti wget 
    apti curl
    apti golang-go 
    apti python2
    apti python3
    apti npm
    apti python3-pip
    apti python-is-python3
    apti python3.10-venv
    apti bpython
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
    apti nano
    apti less 
    apti original-awk 
    apti ssh 
    apti netcat-traditional
    install_tmux
    apti jq 
    apti iputils-ping
    apti autoconf
    apti pciutils
    apti dnsutils
    apti usbutils
    apti telnet
    apti screen
    apti faketime
    apti ftp
    install_gron
    install_anew
    apti iproute2
    apti binwalk
    apti isc-dhcp-client
    install_firefox
    apti chromium
    apti mlocate
    apti feh
    apti ascii
    apti cargo
    install_mdcat
    apti p7zip-full
    apti tor
    apti x11-apps
    apti bat
    apti exa
    apti rdate
    apti socat
    apti ntpdate
    install_funiq
    apti python3.9-venv
    pip install pipx
    install_fzf
    apti gcc-mingw-w64-x86-64
}

function utilsrune {
    install_arsenal
    install_whatportis
    install_ressources
    install_DefaultCredsCheatSheet
    install_gists
}

function crackrune {
    install_hashcat
    apti hydra
    pip3 install name-that-hash
    apti hashcat-utils
    apti pack
    apti cewl
}

function exploitrune {
    install_msf
    install_sliver
    install_pwncat
    apti exploitdb 
    install_empire
}

function osintrune {
    install_onionsearch
    install_holehe
    apti whois
    install_ipinfo
    install_linkedint
}

function codereviewrune {
    apti cloc
    install_semgrep
}

function webrune {
    install_ffuf
    install_gobuster
    install_nuclei
    install_shcheck
    install_subfinder
    install_httpx
    install_testssl
    install_gowitness
    install_ipcdn
    install_amass
    install_assetfinder
    install_fff
    install_meg
    install_unfurl
    install_htmlq
    install_waybackurls
    install_jsloot
    install_ssrfmap
    install_hakip2host
    install_authz0
    install_ysoserial
    install_brb
    install_sqlmap
    install_gau
    install_burp
    install_truffleHog
    install_fuxploider
    apti whatweb
    install_hakrawler
    install_arjun
    install_uro
    install_simplehttpserver
    install_eos
    apti sslscan
    install_bypass403
    install_cookiemonster
    install_jsbeautifier
    install_xLinkFinder
    install_hakrevdns
    install_shuffledns
    install_gf
    install_hike
    install_phpgcc
    install_dnsx
    install_jwttool
    install_gobfuscate
    install_garble
}

function networkrune {
    apti nmap
    apti netdiscover
    apti iptables
    apti arp-scan
    apti arping
    apti arptables
    apti net-tools
    install_rustscan
    install_naabu
    apti proxychains4
    apti masscan
    apti traceroute
    apti openvpn
    apti openresolv
    install_mapcidr
    apti ipcalc
    install_bettercap
    install_dnschef
    apti tshark
    apti wireshark
    apti dsniff
    apti tcpdump
    apti macchanger
}

function adrune {
    install_impacket
    install_cme
    install_ldapdomaindump
    apti ldapsearch
    install_powershell
    apti smbclient
    apti smbmap
    apti rpcbind
    apti chntpw
    apti nbtscan
    install_evil-winrm
    install_pth_toolkit
    install_pcredz
    install_BloodHound_and_friends
    pip3 install pypykatz
    install_krbrelayx
    install_pkinittools
    install_mitm6
    install_Responder
    install_pywhisker
    install_targetedKerberoast
    install_LDAPmonitor
    install_gMSADumper
    install_chisel
    install_petitpotam
    pip install adidnsdump
    install_lsassy
    install_pyGPOabuse
    apti freerdp2-x11
    install_privexchange
    install_changeme
    pip3 install pivotnacci
    install_printnightmare
    install_zerologon
    apti rdesktop
    install_ntlmv1-multi
    install_routersploit
    install_ldaprelayscan
    install_enum4linuxng
    install_certipy
    install_modifyCertTemplate
    install_manspider
    install_pywsus
    install_kerbrute
    install_donpapi
    install_webclientservicescanner
    install_cve-2019-1040-scanner
    install_roadrecon
    apti heimdal-clients
    install_netntlmtosilverticket
    install_ShadowCoerce
    install_dploot
    install_pylaps
    install_DPAT
    install_pywerview
    install_acltoolkit
    install_kutil
    install_ntdsutil.py
    install_ADReaper
}

function wifirune {
    apti wireless-tools
    apti iw
    apti aircrack-ng
    apti reaver
    apti hostapd-wpe
    apti hcxtools
    apti hcxdumptool
    install_eaphammer
}

function reverserune {
    install_volatility
    install_ghidra
}

function rfidrune {
    install_mfdread
    install_proxmark3
}

function voiprune {
    apti voiphopper
    install_sipvicious
    apti sipcrack
    apti sipsak
    apti sipgrep
    install_SeeYouCM-Thief
}

function everyrunes {
    install_default
    utilsrune
    osintrune
    webrune
    networkrune
    reverserune
    exploitrune
    crackrune
    voiprune
    adrune
    wifirune
    rfidrune
    codereviewrune
    cleanup
}

"$@"