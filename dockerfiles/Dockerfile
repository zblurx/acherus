FROM debian

LABEL version=1.2.0
LABEL maintainer=@zblurx

ENV DEBIAN_FRONTEND noninteractive

RUN echo "LC_ALL=en_US.UTF-8" >> /etc/environment
RUN echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen
RUN echo "LANG=en_US.UTF-8" > /etc/locale.conf

RUN apt-get update && apt-get upgrade -y

RUN apt-get install -y locales
RUN locale-gen en_US.UTF-8

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
# RUN /runeforge/runeforge.sh  codereviewrune
# RUN /runeforge/runeforge.sh  reverserune
RUN /runeforge/runeforge.sh  cleanup

WORKDIR /data