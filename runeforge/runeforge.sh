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
    source /root/.bashrc
}

function install_python {
    apti python2
    apti python3
    apti python3-venv
    apti python3-setuptools
    apti python3-pip
    pip install packaging==20.0
    apti python-is-python3
    pip install pipx
}

function install_sudo {
    apti sudo
    cp /etc/hosts ~/hosts.new
    sed -i "s/machine/$( cat /etc/hostname)/g" ~/hosts.new
    cp -f ~/hosts.new /etc/hosts
    rm ~/hosts.new
}

function install_manspider {
    apti tesseract-ocr
    apti antiword
    pipx install git+https://github.com/blacklanternsecurity/MANSPIDER
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
    cp -v /runeforge/files/.ffufrc /root/.ffufrc
}

function install_pretender {
    go install github.com/RedTeamPentesting/pretender@latest
}

function install_credmaster {
    git clone https://github.com/knavesec/CredMaster.git /opt/tools/CredMaster
    virtualenv -p python3 /opt/tools/CredMaster/venv
    source /opt/tools/CredMaster/venv/bin/activate
    python3 -m pip install -r /opt/tools/CredMaster/requirements.txt
    deactivate
}

function install_jsloot {
    go install -v github.com/zblurx/jsloot@latest
}

function install_brb {
    go install -v github.com/zblurx/brb@latest
}

function install_gobuster {
    # https://github.com/OJ/gobuster
    go install -v github.com/OJ/gobuster/v3@latest
}

function install_nuclei {
    # https://github.com/projectdiscovery/nuclei
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    git clone https://github.com/projectdiscovery/fuzzing-templates /opt/tools/nuclei-templates/fuzzing
    usr/local/go/bin/nuclei -update
    usr/local/go/bin/nuclei -ut 
    usr/local/go/bin/nuclei -duc
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
    pipx install git+https://github.com/Hackndo/lsassy.git
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

function install_golang {
    cd /tmp/
    if [[ $(uname -m) = 'x86_64' ]]
    then
        wget -O /tmp/go.tar.gz https://go.dev/dl/go1.20.1.linux-amd64.tar.gz
    elif [[ $(uname -m) = 'aarch64' ]]
    then
        wget -O /tmp/go.tar.gz https://go.dev/dl/go1.20.1.linux-arm64.tar.gz
    fi
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    export PATH=$PATH:/usr/local/go/bin
}

function install_cargo {
    curl https://sh.rustup.rs -sSf | sh -s -- -y
    source $HOME/.cargo/env
}

function install_gron {
    # https://github.com/tomnomnom/gron
    go install -v github.com/tomnomnom/gron@latest
}

function install_bloodhoundpy {
    pipx install git+https://github.com/fox-it/BloodHound.py.git
}

function install_pcredz {
    apti libpcap-dev 
    git clone https://github.com/lgandx/PCredz.git /opt/tools/PCredz
    cd /opt/tools/PCredz
    virtualenv -p python3 venv
    source /opt/tools/PCredz/venv/bin/activate
    python3 -m pip install Cython
    python3 -m pip install python-libpcap
    deactivate
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

function install_enum4linuxng {
    git clone https://github.com/cddmp/enum4linux-ng /opt/tools/enum4linux-ng
    virtualenv -p python3 /opt/tools/enum4linux-ng/venv
    apti smbclient 
    source /opt/tools/enum4linux-ng/venv/bin/activate
    pip install wheel
    pip install -r /opt/tools/enum4linux-ng/requirements.txt
    deactivate
}

function install_krbrelayx {
    git clone https://github.com/dirkjanm/krbrelayx.git /opt/tools/krbrelayx
}

function install_tldr {
    cargo install tealdeer
    /root/.cargo/bin/tldr -u
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

function install_katana {
    go install github.com/projectdiscovery/katana/cmd/katana@latest
}

function install_linkedin2username {
    git clone https://github.com/initstring/linkedin2username.git /opt/tools/linkedin2username
    virtualenv -p python3 /opt/tools/linkedin2username/venv
    source /opt/tools/linkedin2username/venv/bin/activate
    pip install -r /opt/tools/linkedin2username/requirements.txt
    deactivate
}

function install_pre2k {
    pipx install git+https://github.com/garrettfoster13/pre2k
}

function install_proxify {
    go install -v github.com/projectdiscovery/proxify/cmd/proxify@latest
}

function install_dnschef {
    git clone https://github.com/iphelix/dnschef.git /opt/tools/dnschef
    virtualenv -p python3 /opt/tools/dnschef/venv
    source /opt/tools/dnschef/venv/bin/activate
    pip install -r /opt/tools/dnschef/requirements.txt
    deactivate
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
    pipx install git+https://github.com/dirkjanm/mitm6
}

function install_zerologon {
    mkdir /opt/tools/zerologon
    git clone https://github.com/dirkjanm/CVE-2020-1472.git /opt/tools/zerologon
}

function install_targetedKerberoast {
    git clone https://github.com/ShutdownRepo/targetedKerberoast.git /opt/tools/targetedKerberoast
}

function install_DefaultCredsCheatSheet {
    git clone https://github.com/ihebski/DefaultCreds-cheat-sheet.git /opt/tools/DefaultCreds
    virtualenv -p python3 /opt/tools/DefaultCreds/venv
    source /opt/tools/DefaultCreds/venv/bin/activate
    python3 -m pip install -r /opt/tools/DefaultCreds/requirements.txt
    python3 -m pip install .
    deactivate
}

function install_mapcidr {
    go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
}

function install_SeeYouCM-Thief {
    git clone https://github.com/trustedsec/SeeYouCM-Thief.git /opt/tools/SeeYouCM-Thief
    virtualenv -p python3 /opt/tools/SeeYouCM-Thief/venv
    source /opt/tools/SeeYouCM-Thief/venv/bin/activate
    python3 -m pip install -r /opt/tools/SeeYouCM-Thief/requirements.txt
    deactivate
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

function install_adidnsdump {
    pipx install git+https://github.com/dirkjanm/adidnsdump#egg=adidnsdump
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

function install_impersonate-rs {
    git clone https://github.com/zblurx/impersonate-rs /opt/resources/impersonate-rs
    cd /opt/resources/impersonate-rs
    make windows
}

function install_sysinternals {
    mkdir /opt/resources/SysInternals
    cd /opt/resources/SysInternals
    wget https://download.sysinternals.com/files/SysinternalsSuite.zip
}

function install_ressources {
    git clone https://github.com/danielmiessler/SecLists.git --depth 1 /opt/resources/SecLists
    git clone https://github.com/six2dez/OneListForAll.git --depth 0 /opt/resources/OneListForAll
    # git clone https://github.com/carlospolop/PEASS-ng.git /opt/resources/PEASS-ng
    git clone https://github.com/itm4n/PrivescCheck.git /opt/resources/PrivescCheck
    get_last_git_release gentilkiwi/mimikatz mimikatz
    install_impersonate-rs
    # get_last_git_release gentilkiwi/kekeo kekeo
    git clone https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell.git /opt/resources/Amsi-Bypass-Powershell
    git clone https://github.com/PowerShellMafia/PowerSploit.git /opt/resources/PowerSploit
    git clone https://github.com/pry0cc/relevant-wordlist.git /opt/resources/relevant-wordlist
    install_sysinternals
    mkdir /opt/resources/clem9669_wordlist/ && wget https://github.com/clem9669/wordlists/releases/download/22/clem9669_wordlist_small.7z -O /opt/resources/clem9669_wordlist/wordlist-french.7z
    get_last_git_release vletoux/pingcastle PingCastle
}

function set_env(){
    export GO111MODULE=on
    export PATH="$HOME/.poetry/bin:/usr/local/go/bin:/root/.local/bin/:/root/.cargo/bin/:$HOME/.nimble/bin:$PATH"
}

function install_privexchange {
    git clone https://github.com/dirkjanm/PrivExchange.git /opt/tools/PrivExchange
}

function install_crosslinked {
    python3 -m pipx install git+https://github.com/m8sec/crosslinked
}

function install_authz0 {
    go install github.com/hahwul/authz0@latest
}

function install_ipinfo {
    go install github.com/ipinfo/cli/ipinfo@latest
}

function install_eos {
    pipx install git+https://github.com/Synacktiv/eos
}

function install_bypass-url-parser {
    git clone https://github.com/laluka/bypass-url-parser.git /opt/tools/bypass-url-parser
}

function install_pywerview {
    git clone https://github.com/the-useless-one/pywerview.git /opt/tools/pywerview
    cd /opt/tools/pywerview
    apti libkrb5-dev
    python3 -m pipx install pywerview --include-deps --pip-args dsinternals
}

function install_kutil {
    pipx install git+https://github.com/qtc-de/kutil.git
}

function install_pwncat {
    pipx install git+https://github.com/calebstewart/pwncat
}

function install_scarecrow {
    git clone https://github.com/optiv/ScareCrow.git /opt/tools/ScareCrow
    cd /opt/tools/ScareCrow
    apti openssl osslsigncode mingw-w64
    go get github.com/fatih/color
    go get github.com/yeka/zip
    go get github.com/josephspurrier/goversioninfo
    go get github.com/Binject/debug/pe
    go get github.com/awgh/rawreader
    go build ScareCrow.go
}

function install_cve-2019-1040-scanner {
    git clone https://github.com/fox-it/cve-2019-1040-scanner.git /opt/tools/remove-mic-scanner
}

function install_webclientservicescanner {
    pipx install git+https://github.com/Hackndo/WebclientServiceScanner.git
}

function install_gMSADumper {
    git clone https://github.com/micahvandeusen/gMSADumper.git /opt/tools/gMSADumper
    virtualenv -p python3 /opt/tools/gMSADumper/venv
    source /opt/tools/gMSADumper/venv/bin/activate
    python3 -m pip install -r /opt/tools/gMSADumper/requirements.txt
    deactivate
}

function install_roadrecon {
    pipx install roadrecon
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
    virtualenv -p python3 /opt/tools/pywsus/venv
    source /opt/tools/pywsus/venv/bin/activate
    python3 -m pip install -r /opt/tools/pywsus/requirements.txt
    deactivate
}

function install_eaphammer {
    git clone https://github.com/s0lst1c3/eaphammer.git /opt/tools/eaphammer
    cd /opt/tools/eaphammer
    virtualenv -p python3 venv
    source /opt/tools/eaphammer/venv/bin/activate
    echo y | ./ubuntu-unattended-setup
    deactivate
}

function install_acltoolkit {
    pipx install git+https://github.com/zblurx/acltoolkit
}

function install_arsenal {
    python3 -m pipx install git+https://github.com/Orange-Cyberdefense/arsenal.git
}

function install_ldapsearch-ad {
    pipx install git+https://github.com/yaap7/ldapsearch-ad.git
}

function install_ldapnomnom {
    go install github.com/lkarlslund/ldapnomnom@latest
}

function install_neo4j {
    wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
    echo 'deb https://debian.neo4j.com stable 4.4' > /etc/apt/sources.list.d/neo4j.list
    apt-get update
    apti apt-transport-https
    apti neo4j
    neo4j-admin set-initial-password acherus
    mkdir -p /usr/share/neo4j/logs/
    touch /usr/share/neo4j/logs/neo4j.log
}

function install_pypykatz {
    pipx install git+https://github.com/skelsec/pypykatz.git
}

function install_msprobe {
    pipx install git+https://github.com/puzzlepeaches/msprobe.git
}

function install_BloodHound {
    # git clone https://github.com/BloodHoundAD/BloodHound /opt/tools/BloodHound
    # npm install -g electron-packager
    # cd /opt/tools/BloodHound
    # npm install --force
    # npm run build:linux

    # apti bloodhound
    mkdir /opt/tools/BloodHound
    cd /opt/tools/BloodHound
    curl --silent "https://api.github.com/repos/BloodHoundAD/BloodHound/releases/latest" | jq ".assets[] | .browser_download_url" | grep linux-x64 | xargs wget
    unzip BloodHound-linux-x64.zip && rm BloodHound-linux-x64.zip

    # install config
    mkdir -p ~/.config/bloodhound/
    cp /runeforge/files/bloodhound_config.json ~/.config/bloodhound/config.json
}

function install_pyGPOabuse {
    git clone https://github.com/Hackndo/pyGPOAbuse.git /opt/tools/pyGPOAbuse
}

function install_tlsx {
    go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
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

function install_serviceDetector {
    git clone https://github.com/tothi/serviceDetector.git /opt/tools/serviceDetector
}

function install_fbhq {
    pipx install git+https://github.com/zblurx/fbhq
}

function install_donpapi {
    git clone https://github.com/login-securite/DonPAPI.git /opt/tools/DonPAPI
    cd /opt/tools/DonPAPI
    apti swig
    git checkout MFA # TODO change quand ca sera merge
    python3 -m pipx install .
}

function install_ldeep {
    pipx install git+https://github.com/franc-pentest/ldeep.git
}

function install_ritm {
    pipx install git+https://github.com/Tw1sm/RITM
}

function install_searchsploit {
    git clone https://gitlab.com/exploit-database/exploitdb /opt/tools/exploitdb
    cd /opt/tools/exploitdb
    git config pull.rebase false
    ln -sf /opt/tools/exploitdb/searchsploit /usr/local/bin/searchsploit
    cp -n /opt/tools/exploitdb/.searchsploit_rc ~/
    sed -i 's/\(.*[pP]aper.*\)/#\1/' ~/.searchsploit_rc
    sed -i 's/opt\/exploitdb/opt\/tools\/exploitdb/' ~/.searchsploit_rc
    searchsploit -u
    echo 'cest bon merci monsieur' # Tout ca pour avoir un return code 0 ...
}

function install_graudit {
    git clone https://github.com/wireghoul/graudit.git /opt/tools/graudit
}

function install_holehe {
    pipx install git+https://github.com/megadose/holehe.git
}

function install_nndefaccts {
    git clone https://github.com/nnposter/nndefaccts.git /opt/tools/nndefaccts
    cp /opt/tools/nndefaccts/http-default-accounts-fingerprints-nndefaccts.lua /usr/share/nmap/nselib/data/http-default-accounts-fingerprints.lua
}

function install_gau {
    # https://github.com/lc/gau
    go install github.com/lc/gau/v2/cmd/gau@latest
}

function install_coercer {
    pipx install git+https://github.com/p0dalirius/Coercer.git
}

function install_gf { 
    go install -v github.com/tomnomnom/gf@latest
    mkdir ~/.gf
    wget https://raw.githubusercontent.com/tomnomnom/gf/master/gf-completion.bash -O /root/.gf/.gf_completion.bash 
    echo 'source /root/.gf/.gf_completion.bash' >> ~/.bashrc
    cp -r /root/go/src/github.com/tomnomnom/gf/examples ~/.gf
    git clone https://github.com/zblurx/gf-patterns.git /opt/resources/gf-patterns/
    cp /opt/resources/gf-patterns/*.json ~/.gf
}

function install_certsync {
    pipx install git+https://github.com/zblurx/certsync
}

function install_xLinkFinder {
    git clone https://github.com/xnl-h4ck3r/xnLinkFinder.git /opt/tools/xnLinkFinder
}

function install_ntdsutil.py {
    pipx install git+https://github.com/zblurx/ntdsutil.py
}

function install_amass {
    # https://github.com/OWASP/Amass
    go install -v github.com/OWASP/Amass/v3/...@latest
}

function install_shcheck {
    pipx install git+https://github.com/santoru/shcheck.git
}

function install_sliver {
    git clone https://github.com/BishopFox/sliver.git /opt/tools/sliver
    cd /opt/tools/sliver
    ./go-assets.sh
    make
}

function install_impacket {
    # https://github.com/fortra/impacket
    git clone https://github.com/ThePorgs/impacket.git /opt/tools/impacket
    cd /opt/tools/impacket
    python3 -m pipx install .
}

function install_impacket-old {
    # https://github.com/fortra/impacket
    git clone https://github.com/fortra/impacket.git /opt/tools/impacket-old
    virtualenv -p python3 /opt/tools/impacket-old/venv
    source /opt/tools/impacket-old/venv/bin/activate
    python3 -m pip install .
    deactivate
}

function install_cme {
    apt-get install -y libssl-dev libxml2-dev openssl autoconf g++ python3-dev git libxslt-dev libffi-dev build-essential libkrb5-dev
    git clone https://github.com/Porchetta-Industries/CrackMapExec.git /opt/tools/CrackMapExec
    cd /opt/tools/CrackMapExec
    python3 -m pipx install .
    mkdir -p ~/.cme
    cp -v /runeforge/files/cme.conf ~/.cme/cme.conf
}

function install_proxmark3 {
    apt-get install -y --no-install-recommends git ca-certificates build-essential pkg-config libreadline-dev gcc-arm-none-eabi libnewlib-dev qtbase5-dev libbz2-dev libbluetooth-dev libpython3-dev
    git clone https://github.com/RfidResearchGroup/proxmark3.git /opt/tools/proxmark3
    cd /opt/tools/proxmark3
    make clean && make -j
    make install
}

function install_masky {
    python3 -m pipx install git+https://github.com/Z4kSec/Masky.git
}

function install_fzf {
    git clone https://github.com/junegunn/fzf ~/.fzf
    ~/.fzf/install --all
}

function install_certipy {
    python3 -m pipx install git+https://github.com/ly4k/Certipy.git
}

function install_ldapdomaindump {
    pipx install git+https://github.com/dirkjanm/ldapdomaindump
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

function install_uro {
    pip3 install uro
}

function install_arjun {
    pip3 install arjun
}

function install_keepwn {
    pipx install git+https://github.com/Orange-Cyberdefense/KeePwn
}

function install_bettercap {
    apti build-essential
    apti libpcap-dev
    apti libnetfilter-queue-dev
    apti libusb-1.0-0-dev
    go install -v github.com/bettercap/bettercap@latest
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
    gem install evil-winrm
}

function install_msf {
    mkdir /tmp/metasploit_install
    cd /tmp/metasploit_install || exit
    curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
    cd /opt/tools || exit
    rm -rf /tmp/metasploit_install
}

function install_pack {
    git clone https://github.com/Hydraze/pack.git /opt/tools/pack
}

function install_hashcat {
    apti hashcat
    mkdir -p /opt/resources/hashcat_rules/
    git clone https://github.com/clem9669/hashcat-rule.git /opt/resources/hashcat_rules/clem9669 
    wget https://raw.githubusercontent.com/NotSoSecure/password_cracking_rules/master/OneRuleToRuleThemAll.rule -O /opt/resources/hashcat_rules/OneRuleToRuleThemAll.rule
    wget https://raw.githubusercontent.com/NSAKEY/nsa-rules/master/_NSAKEY.v2.dive.rule -O /opt/resources/hashcat_rules/nsa_dive.rule
    wget https://github.com/rarecoil/pantagrule/raw/master/rules/hashesorg.v6/pantagrule.hashorg.v6.popular.rule.gz -O /opt/resources/hashcat_rules/pantagrule.hashorg.v6.popular.rule.gz
    apti hashcat-utils # change
}

function install_whatportis {
    pipx install whatportis
    echo y | whatportis --update
}

function install_dhcpp {
    go install github.com/zblurx/dhcpp@latest
}

function install_nimcrypt {
    git clone https://github.com/icyguider/Nimcrypt2.git /opt/tools/Nimcrypt2
    sudo apt-get install gcc mingw-w64 xz-utils -y
    nimble install winim nimcrypto docopt ptr_math strenc -y
    nim c -d=release --cc:gcc --embedsrc=on --hints=on --app=console --cpu=amd64 --out=nimcrypt nimcrypt.nim
}

function install_jsbeautifier {
    pip3 install jsbeautifier
}

function install_bloodhound-import {
    pipx install git+https://github.com/fox-it/bloodhound-import.git
}

function install_ysoserial {
    mkdir /opt/tools/ysoserial/
    wget https://jitpack.io/com/github/frohoff/ysoserial/master-SNAPSHOT/ysoserial-master-SNAPSHOT.jar -O /opt/tools/ysoserial/ysoserial.jar
}

function install_dploot {
    pipx install git+https://github.com/zblurx/dploot
}

function install_dumpsmbshare {
    git clone https://github.com/p0dalirius/DumpSMBShare.git /opt/tools/DumpSMBShare
    virtualenv -p python3 /opt/tools/DumpSMBShare/venv
    source /opt/tools/DumpSMBShare/venv/bin/activate
    python3 -m pip install -r /opt/tools/DumpSMBShare/requirements.txt
    deactivate
}

function install_cookiemonster {
    go install github.com/iangcarroll/cookiemonster/cmd/cookiemonster@latest
}

function install_ghidra {
    apti openjdk-11-jdk
    mkdir /opt/tools/ghidra
    cd /opt/tools/ghidra
    curl --silent "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest" | jq ".assets[] | .browser_download_url" | xargs wget 
}

function install_lazagne {
    apti openjdk-11-jdk
    mkdir /opt/tools/lazagne
    cd /opt/tools/lazagne
    curl --silent "https://api.github.com/repos/AlessandroZ/LaZagne/releases/latest" | jq ".assets[] | .browser_download_url" | xargs wget 
}

function install_volatility {
    git clone https://github.com/volatilityfoundation/volatility3.git /opt/tools/volatility3
    cd /opt/tools/volatility3
    python3 -m pipx install .
}

function install_firefox {
    apti firefox-esr
    echo "pref(\"gfx.xrender.enabled\", true);" >> /etc/firefox-esr/firefox-esr.js;
    mkdir -p /opt/resources/firefox-extensions
    wget https://addons.mozilla.org/firefox/downloads/file/3862036/firefox_multi_account_containers-8.0.1-fx.xpi -O /opt/resources/firefox-extensions/firefox_multi_account_containers-8.0.1-fx.xpi
    wget https://addons.mozilla.org/firefox/downloads/file/3611407/foxyproxy_standard-7.5.1.xpi -O /opt/resources/firefox-extensions/foxyproxy_standard-7.5.1.xpi
    # user_pref("browser.urlbar.placeholderName", "DuckDuckGo");
    # user_pref("browser.slowStartup.samples", 3);
    # user_pref("browser.newtabpage.activity-stream.improvesearch.topSiteSearchShortcuts.havePinned", "duckduckgo");
}

function install_onionsearch {
    pip3 install onionsearch
}

function install_rusthound {
    git clone https://github.com/OPENCYBER-FR/RustHound.git /opt/tools/RustHound
    apti gcc libclang-dev clang libclang-dev libgssapi-krb5-2 libkrb5-dev libsasl2-modules-gssapi-mit musl-tools gcc-mingw-w64-x86-64
    cd /opt/tools/RustHound
    make install
}

function install_BloodHound_and_friends {
    install_neo4j
    install_BloodHound
    install_bloodhoundpy
    install_rusthound
    install_BloodHoundCustomQueries
    install-bloodhound-quickwin
    install_bloodhound-import
    install_cypheroth
    install_fbhq
}

function install_pth_toolkit {
    git clone https://github.com/byt3bl33d3r/pth-toolkit.git /opt/tools/pth-toolkit
}

function install_sipvicious {
    pipx install git+https://github.com/EnableSecurity/sipvicious.git
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
    set_env
    apt-get upgrade -y
    apt-get autoremove -y
    apt-get clean
    go clean --cache
    updatedb
}

function install_default {
    install_bashrc
    apti software-properties-common
    add-apt-repository contrib
    add-apt-repository non-free
    apti apt-utils
    apti man
    apti git
    apti gnupg2
    apti bash-completion
    install_sudo
    apti openssl
    apti ca-certificates
    apti wget 
    apti curl
    apti pkg-config
    install_golang
    apti npm
    apti ruby-dev
    install_python
    install_cargo
    apti php
    apti gem
    apti virtualenv
    apti zip
    apti moreutils #sponge etc.
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
    install_tmux
    apti jq 
    apti iputils-ping
    apti autoconf
    apti pciutils
    apti dnsutils
    apti usbutils
    apti telnet
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
    install_mdcat
    apti p7zip-full
    apti tor
    apti x11-apps
    apti bat
    apti exa
    apti rdate
    apti socat
    apti ntpdate
    apti libqrencode4
    install_fzf
    apti gcc-mingw-w64-x86-64
}

function utilsrune {
    set_env
    install_arsenal
    install_whatportis
    install_ressources
    install_DefaultCredsCheatSheet
    install_gists
    install_ipinfo
    install_tldr
}

function crackrune {
    set_env
    install_hashcat
    pip3 install name-that-hash
    install_pack
    apti cewl 
}

function exploitrune {
    set_env
    install_msf
    # install_sliver
    install_searchsploit
    install_pwncat
    # install_empire
}

function osintrune {
    set_env
    install_onionsearch
    install_holehe
    apti whois
    install_crosslinked
    install_linkedin2username
    install_truffleHog
}

function codereviewrune {
    set_env
    apti cloc
    install_graudit
}

function webrune {
    set_env
    install_ffuf
    install_gobuster
    install_nuclei
    install_shcheck
    install_subfinder
    install_httpx
    install_testssl
    install_gowitness
    install_katana
    install_proxify
    install_msprobe
    install_ipcdn
    install_amass
    install_assetfinder
    install_fff
    install_meg
    install_unfurl
    install_htmlq
    install_waybackurls
    install_jsloot
    install_authz0
    install_ysoserial
    install_tlsx
    install_brb
    install_sqlmap
    install_gau
    install_burp
    apti whatweb
    install_arjun
    install_uro
    install_simplehttpserver
    install_eos
    install_bypass-url-parser
    install_cookiemonster
    install_jsbeautifier
    install_xLinkFinder
    install_gf
    install_hike
    install_phpgcc
    install_dnsx
}

function networkrune {
    set_env
    apti nmap
    install_nndefaccts
    apti netdiscover
    apti iptables
    apti arp-scan
    apti arping
    apti arptables
    apti net-tools
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
    install_dhcpp
    apti tcpdump
    apti macchanger
}

function adrune {
    set_env
    install_impacket
    install_cme
    install_ldapdomaindump
    apti ldap-utils
    apti rpcbind
    apti chntpw
    install_ldapnomnom
    install_coercer
    install_keepwn
    apti nbtscan
    install_ritm
    install_pypykatz
    install_evil-winrm
    install_pth_toolkit
    install_credmaster
    install_ldeep
    install_ldapsearch-ad
    install_pcredz
    install_BloodHound_and_friends
    install_pre2k
    install_krbrelayx
    install_pretender
    install_mitm6
    install_Responder
    # install_targetedKerberoast
    install_LDAPmonitor # change
    install_gMSADumper
    # install_serviceDetector
    install_chisel
    # install_petitpotam
    install_adidnsdump
    install_lsassy
    install_pyGPOabuse
    install_certsync
    install_scarecrow
    apti freerdp2-x11
    install_privexchange
    install_zerologon
    apti rdesktop
    install_ntlmv1-multi
    install_enum4linuxng
    install_certipy
    install_manspider
    install_pywsus
    install_dumpsmbshare
    install_kerbrute
    install_donpapi
    install_webclientservicescanner
    install_masky
    install_cve-2019-1040-scanner
    install_roadrecon
    apti heimdal-clients
    install_dploot
    install_pywerview
    install_acltoolkit
    install_kutil
    install_ntdsutil.py
}

function wifirune {
    set_env
    apti wireless-tools
    apti iw
    apti aircrack-ng
    apti reaver
    apti hcxtools
    apti hcxdumptool
    install_eaphammer
}

function reverserune {
    set_env
    install_volatility
    install_ghidra
}

function rfidrune {
    set_env
    install_mfdread
    install_proxmark3
}

function voiprune {
    set_env
    install_sipvicious
    install_SeeYouCM-Thief
}

"$@"