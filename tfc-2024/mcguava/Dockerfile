FROM ubuntu:24.10

RUN apt-get update && apt-get install -y \
    socat \
    gdb \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /home/ctf

COPY guava /home/ctf/guava
COPY flag.txt /home/ctf/flag.txt

RUN chmod +x /home/ctf/guava

WORKDIR /home/ctf

EXPOSE 1337

CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:/home/ctf/guava