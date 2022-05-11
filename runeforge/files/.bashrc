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
    ipinfo prips "$@" | httpx -sr -o httpx-low-fruits.out -title -sc -td -p 80,81,143,300,443,591,593,832,981,1010,1090,1098,1099,1311,1617,2082,2087,2095,2096,2480,2990,3000,3128,3333,4243,4444,4445,4567,4711,4712,4786,4848,4993,5000,5104,5108,5432,5555,5556,5601,5800,6066,6543,7000,7001,7002,7003,7004,7070,7071,7396,7474,8000,8001,8002,8003,8008,8009,8014,8042,8060,8069,8080,8081,8088,8090,8091,8118,8123,8161,8172,8222,8243,8280,8281,8333,8443,8500,8686,8834,8880,8888,8983,9000,9001,9002,9003,9012,9043,9060,9080,9090,9091,9200,9443,9503,9800,9981,10443,10999,11006,11099,11111,12443,15672,16080,18091,18092,20720,28017,45000,45001,47001,47002,50500
}

export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
export TZ='Europe/Paris'
export PATH="$HOME/.poetry/bin:/root/.local/bin/:/root/.cargo/bin/:$PATH"
export GRDIR=/opt/tools/graudit/signatures
export HISTFILE=/data/.bash_history
export PROMPT_COMMAND='history -a'

