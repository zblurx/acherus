# Acherus: The Docker Hold

[<img src="img/acherus-le-fort-d-ebene.jpg">](https://hub.docker.com/r/zblurx/acherus)

***"Behold, Acherus, the grand citadel of death! It has no equal in this world! Not even the mighty Naxxramas could withstand a direct assault from the Ebon Hold."***  *Instructor Razuvious*

**Acherus** is a containerized hacking environment, based on kali image, and inspired from [Exegol](https://github.com/ShutdownRepo/Exegol) and [dwn](https://github.com/Sensepost/dwn). It aim to simplify deployment and maintainability of an up-to-date hacking environment, with the ability to throw it and recreate it at any time.

**Acherus** comes with a binary written in Go that act as a docker-client rewrite specifically for Acherus.

## Warning

This project is a low-cost [Exegol](https://github.com/ShutdownRepo/Exegol), I'm using it because I have fun to and it's implemented with all dotfiles and keybinds I like, but if you are searching for a stronger / stable one, go for ***Exegol***. 

## Requirements

- [Docker](https://docs.docker.com/get-docker/)
- [Golang](https://go.dev/dl/)
- Root user or user in *docker* group
- A bit of disk space : <img src="https://img.shields.io/docker/image-size/zblurx/acherus">

## Installation

To install acherus binary, type the command below.

```
go install github.com/zblurx/acherus@latest
```

*Note: Make sure that your go binary path is in your **PATH** variable !*

## Quick Start

```
$ acherus init
[*] Pulling Acherus. Can take some time...
[*] Ready !
$ acherus go
root@acherus [/] ~>
```

## Usage
```
$ acherus
Usage:
  acherus [command]

Available Commands:
  completion  generate the autocompletion script for the specified shell
  destroy     Delete targeted container
  go          Execute and attach to container
  help        Help about any command
  init        Build image
  list        List available container
  reset       Reset Image
  suspend     Suspend targeted Acherus Container

Flags:
  -h, --help      help for acherus
  -v, --verbose   Verbose mode (usefull for debugging)

Use "acherus [command] --help" for more information about a command.
```

### List

To list image and containers:

```
$ acherus list
[*] Image List

|--------------|-----------------------|----------|
|      ID      |         TAGS          |   SIZE   |
|--------------|-----------------------|----------|
| d36dae842e7d | zblurx/acherus:latest | 13.83 GB |
|--------------|-----------------------|----------|

[*] Container List

|----------|-----------------------|--------------|--------------------------|
|   NAME   |         IMAGE         |      ID      |          STATUS          |
|----------|-----------------------|--------------|--------------------------|
| /acherus | zblurx/acherus:latest | c8c5ca0f476c | Exited (0) 2 minutes ago |
|----------|-----------------------|--------------|--------------------------|

```

### Init

To install [Acherus docker image](https://hub.docker.com/r/zblurx/acherus), you can use **acherus init**:

```
$ acherus init --help
Build image

Usage:
  acherus init [flags]

Flags:
  -d, --dockerfile-path string   Dockerfile path
  -h, --help                     help for init
  -l, --local                    Load Acherus from a local Dockerfile

Global Flags:
  -v, --verbose   Verbose mode (usefull for debugging)

$ acherus init
[*] Pulling Acherus. Can take some time...
[*] Ready !
```

### Go
**acherus go** is the command to create the container and execute commands in it:

```
$ acherus go --help
Execute and attach to container

Usage:
  acherus go [flags]

Flags:
  -d, --detach           Don't attach to the container
  -e, --execute string   Execute specific command (default is /bin/bash)
  -h, --help             help for go
  -l, --local            Create container based on local image
  -m, --mount string     Mount directory into acherus container (-m "source:dest")
  -n, --nat              Nat the container (default is binded to host)
      --netadmin         Create a container that can interact with network interfaces
      --privileged       Create a container in privileged mode
      --recreate         Force creation of the container (if the container already exists, will delete it)
  -t, --tag string       Tag the specifc container (default "acherus")

Global Flags:
  -v, --verbose   Verbose mode (usefull for debugging)

$ acherus go
root@acherus [/] ~>
```

## Persistence

Each container has a shared folder with the host computer, located in ```~/.acherus/acherus[-tag]``` on the host and in /data in the container. Command history is backed up into this directory, so you can access it even outside the container, in addition from Responder and Metasploit logs.

## Keybinds

Even if Acherus uses bash, it hold a bunch of keybinds and aliases to speed up everything:
```bash
Keybinds:
Ctrl+n -> cd ..
Ctrl+k -> cd /data
Ctrl+r -> fzf history


Aliases:
**Lots of commands**
a="arsenal"
d="cd data"
publicip='curl ifconfig.me'
[...] (Check in runeforge/files/.bash_aliases)
```

## GUI

Acherus supports GUI applications on Linux. For exemple, you can use firefox, wireshark, bloodhound, and many more !

## Network

By default, Acherus bind the container to your host network interfaces. If you want to run the container on it's own network namespace just do:

```bash
$ acherus go --nat [...]
```

If, somehow, you need to use an isolated network namespace, but need host network capability (for example, connect to an openvpn server only in the acherus container) there is an option for that:

```bash
$ acherus go --nat --netadmin [...]
```

***If network is not working anymore after vpn connection, it's dns fault***

If you need wifi capabilities, for example to use a specific wifi card, just use the --privileged option:

```bash
$ acherus go --privileged
```
