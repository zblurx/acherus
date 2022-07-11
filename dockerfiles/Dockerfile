FROM kalilinux/kali-rolling

LABEL version=1.1.1
LABEL maintainer=@zblurx

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get upgrade -y

COPY runeforge /runeforge

RUN chmod +x /runeforge/runeforge.sh

# RUN /runeforge/runeforge.sh everyrunes
RUN /runeforge/runeforge.sh  install_default
RUN /runeforge/runeforge.sh  utilsrune
RUN /runeforge/runeforge.sh  osintrune
RUN /runeforge/runeforge.sh  webrune
RUN /runeforge/runeforge.sh  networkrune
RUN /runeforge/runeforge.sh  exploitrune
RUN /runeforge/runeforge.sh  crackrune
RUN /runeforge/runeforge.sh  voiprune
RUN /runeforge/runeforge.sh  adrune
RUN /runeforge/runeforge.sh  wifirune
RUN /runeforge/runeforge.sh  rfidrune
RUN /runeforge/runeforge.sh  codereviewrune
RUN /runeforge/runeforge.sh  reverserune
RUN /runeforge/runeforge.sh  cleanup

WORKDIR /data