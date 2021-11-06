FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get upgrade -y

COPY runeforge /runeforge

RUN chmod +x /runeforge/runeforge.sh

RUN /runeforge/runeforge.sh install_default
RUN /runeforge/runeforge.sh spe_network
RUN /runeforge/runeforge.sh spe_web
RUN /runeforge/runeforge.sh spe_ad
RUN /runeforge/runeforge.sh spe_wifi
RUN /runeforge/runeforge.sh cleanup