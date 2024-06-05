FROM debian:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y python3 python3-requests libcurl4-openssl-dev libjsoncpp-dev

COPY ./build/jproxy /jproxy

ENV PYTHONUNBUFFERED=1

EXPOSE 8810
USER root
CMD ["/jproxy"]
