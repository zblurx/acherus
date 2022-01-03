case $- in
    *i*) ;;
      *) return;;
esac

HISTCONTROL=ignoreboth

shopt -s histappend

HISTSIZE=2000
HISTFILESIZE=4000

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

export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
export PATH="$HOME/.poetry/bin:/root/.local/bin/:$PATH"
export HISTFILE=/data/.bash_history
export PROMPT_COMMAND='history -a'
