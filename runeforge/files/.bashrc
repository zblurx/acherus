case $- in
    *i*) ;;
      *) return;;
esac

HISTCONTROL=ignoreboth

shopt -s histappend

HISTSIZE=4000
HISTFILESIZE=8000

shopt -s checkwinsize

if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi                                                                                                                                                                                                                                   
                                                                                                                                                                             
force_color_prompt=yes                                                                                                                                                                                                                     
                                                                                                                                                                                                                                           
if [ -n "$force_color_prompt" ]; then                                                                                                                                                                                                      
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then                                                                                                                                                                                                                                                                                                                                                     
        color_prompt=yes
    else
        color_prompt=
    fi
fi

if [ "$color_prompt" = yes ]; then
    PS1='\[\033[01;36m\]\u@\H\[\033[00m\] [\[\033[01;31m\]\w\[\033[00m\]] \[\033[01;35m\]~>\[\033[00m\] '
else
    PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt

if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'

    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
    alias diff='diff --color=auto'
    alias ip='ip --color=auto'

fi

if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi


# useful functions
function mkcd(){
mkdir $1
cd $1
}

function td(){
directory=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
mkdir /tmp/$directory
cd /tmp/$directory
}

function tf(){
file=tf-$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 5 | head -n 1)
vim /tmp/$file
echo $file
}

function funiq(){
    sort -u "$@" | sponge "$@"
}

function cl() {
    DIR="$*";
        # if no DIR given, go home
        if [ $# -lt 1 ]; then
                DIR=$HOME;
    fi;
    builtin cd "${DIR}" && \
    # use your preferred ls command
        ls
}

function httpx-lowfruits(){
    # lowfruits by jdi
    ipinfo prips "$@" | httpx -sr -t 100 -rl 250 -o httpx-low-fruits.out -title -sc -td -p 80,443,8080,8000,8009,8888,8443,9443,10443,7000-7004,8000-8003,9000-9003,7070,3000,4567,8081-8087
}

[ -f ~/.fzf.bash ] && source ~/.fzf.bash
# fzf stolen from snovvcrash
function SharpCollection() {
    `curl -sSL "https://api.github.com/repos/Flangvik/SharpCollection/git/trees/master?recursive=1" | jq -r ".tree[].path" | grep \\.exe | while read line; do echo "curl -sSL https://github.com/Flangvik/SharpCollection/raw/master/$line -o ${line#*/}"; done | fzf --tac --cycle --height=~50% --color=16` 
}

# function Ffuf-w() { 
#     `([ -d /opt/resources/OneListForAll ] && find /opt/resources/OneListForAll/ -maxdepth 2 -type f -name "*.txt") | sort | while read line; do echo "ffuf -w $line -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36' -ic -sf -u "; done | fzf --tac --cycle --height=~50% --color=16 --print-query` 
# }

# function Httpx-p() { 
#     echo `(echo 'httpx -sc -fr -location -title -server -td -method -ip -cname -cdn -p "80,81,443,1080,3000,3128,7001,7002,8080,8443,8888" -t 15 -l'; echo 'httpx -sc -fr -location -title -server -td -method -ip -cname -cdn -t 15 -l') | fzf --tac --cycle --height=~50% --color=16` 
# }

export GOPATH="$HOME/go"
export TZ='Europe/Paris'
export PATH="$HOME/.poetry/bin:/usr/local/go/bin:$GOPATH/bin:/root/.local/bin/:/root/.cargo/bin/:$HOME/.nimble/bin:$PATH"
export GRDIR=/opt/tools/graudit/signatures
export HISTFILE=/data/.bash_history
export HISTTIMEFORMAT="%F %T "
export PROMPT_COMMAND='history -a'
export LC_ALL=en_US.UTF-8

