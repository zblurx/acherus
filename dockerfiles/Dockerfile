FROM kalilinux/kali-rolling

LABEL version=1.0
LABEL maintainer=@zblurx

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get upgrade -y

COPY runeforge /runeforge

RUN chmod +x /runeforge/runeforge.sh

RUN /runeforge/runeforge.sh everyrunes

WORKDIR /data