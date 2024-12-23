# Utils

alias cat='batcat --pager never'
alias ..='cd ..'
alias ..2="cd ../.."
alias ..3="cd ../../.."
alias ..4="cd ../../../.."
alias ..5="cd ../../../../.."
alias cat_original='/usr/bin/cat'
alias ls='exa'
alias l='exa -1F'
alias la='exa -la'
alias ll='exa -laF'
alias tea='tee -a'
alias apts='apt search'
alias aptu='apt update'
alias ping="ping -c 5"
alias apti='apt install -y'
alias uncolor='sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g"'
alias ls_original='/usr/bin/ls'
alias simplehttpserverpy='python3 -m http.server'
alias follow="tail -f -n +1"
alias data="cd /data"
alias d='cd /data'
alias tmux="tmux -u"
alias cs="xclip -selection clipboard "
alias resources='cd /opt/resources'
alias cpv='rsync -ah --info=progress2'
alias tools='cd /opt/tools'
alias rm='rm -I --preserve-root'
alias rmr='rm -rI --preserve-root'
alias rm_original='/usr/bin/rm'
alias ve='virtualenv -p python3 venv'
alias va='source ./venv/bin/activate'
alias myip='ipinfo myip --nocache'
alias histg="history | grep"
alias chmx='chmod +x'
alias ports='netstat -tunlpa'
alias wget='wget -c'
alias proxychains='proxychains4'
alias less='less -RN --mouse --wheel-lines=3'
alias toqr='qrencode -o - | feh --force-aliasing -FZ -'

# Tools

alias seclists='cd /opt/resources/SecLists'
alias onelistforall='cd /opt/resources/OneListForAll'
alias sqlmap='python3 /opt/tools/sqlmap/sqlmap.py'
alias burp='/opt/tools/burp/BurpSuiteCommunity'
alias searchcreds='/opt/tools/DefaultCreds/venv/bin/python /opt/tools/DefaultCreds/creds search'
alias creds='/opt/tools/DefaultCreds/venv/bin/python /opt/tools/DefaultCreds/creds'
alias a="arsenal"
alias chromium='chromium --no-sandbox'
alias bhimport='bloodhound-import -du neo4j -dp acherus'
alias enum4linux-ng='/opt/tools/enum4linux-ng/venv/bin/python /opt/tools/enum4linux-ng/enum4linux-ng.py'
alias msfconsole='msfconsole -H /root/.msfhistory'
alias krbrelayx='python3 /opt/tools/krbrelayx/krbrelayx.py'
alias graudit='/opt/tools/graudit/graudit'
alias pkinittools='cd /opt/tools/PKINITtools'
alias targetedKerberoast='python3 /opt/tools/targetedKerberoast/targetedKerberoast.py'
alias PetitPotam='python3 /opt/tools/PetitPotam/PetitPotam.py'
alias ldapmonitor='python3 /opt/tools/LDAPmonitor/python/pyLDAPmonitor.py'
alias responder='python3 /opt/tools/Responder/Responder.py'
alias bloodhound='nohup neo4j console & sleep 10 && /opt/tools/BloodHound/BloodHound-linux-x64/BloodHound --no-sandbox --disable-dev-shm-usage > /dev/null &'
alias hashcat='/usr/bin/hashcat --potfile-path=/data/hashcat.pot'
alias impacket-examples='cd /opt/tools/impacket/examples'
alias thief.py='python3 /opt/tools/SeeYouCM-Thief/thief.py'
alias eaphammer='/opt/tools/eaphammer/venv/bin/python /opt/tools/eaphammer/eaphammer'
alias printerbug.py='python3 /opt/tools/krbrelayx/printerbug.py'
alias cypheroth='/opt/tools/cypheroth/cypheroth.sh'
alias bhqc.py='python3 /opt/tools/bloodhound-quickwin/bhqc.py'
alias gMSADumper='python3 /opt/tools/gMSADumper/gMSADumper.py'
alias phpgcc='php /opt/tools/phpgcc/phpgcc'
alias ysoserial='java -jar /opt/tools/ysoserial/ysoserial.jar'
alias jndi-exploit-kit='java -jar /opt/tools/JNDI-Exploit-Kit/JNDI-Exploit-Kit.jar'
alias credmaster.py='/opt/tools/Credmaster/venv/bin/python /opt/tools/Credmaster/credmaster.py'
alias DumpSMBShare.py='/opt/tools/DumpSMBShare/venv/bin/python /opt/tools/DumpSMBShare/DumpSMBShare.py'
alias dnschef.py='/opt/tools/dnschef/venv/bin/python /opt/tools/dnschef/dnschef.py'
alias pywsus.py='/opt/tools/pywsus/venv/bin/python /opt/tools/pywsus/pywsus.py'
alias linkedin2username.py='/opt/tools/linkedin2username/venv/bin/python /opt/tools/linkedin2username/linkedin2username.py'
alias dns='cat /etc/resolv.conf'
alias nxc-bh-off="sed -i 's/bh_enabled = True/bh_enabled = False/g' /root/.nxc/nxc.conf && cat /root/.nxc/nxc.conf | grep --color=never 'bh_enabled ='"
alias nxc-bh-on="sed -i 's/bh_enabled = False/bh_enabled = True/g' /root/.nxc/nxc.conf && cat /root/.nxc/nxc.conf | grep --color=never 'bh_enabled ='"
