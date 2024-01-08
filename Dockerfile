FROM kalilinux/kali-rolling

# Set the working directory
WORKDIR /app

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
    wget \
    curl \
    tar \
    make \
    nano \
    pv \
    ipcalc \
    lolcat \
    git \
    jq \
    python3 \
    python3-netaddr \
    python3-tqdm \
    python3-pip \
    python3-termcolor \
    whois \
    nmap \
    xsltproc \
    dirsearch \
    unzip \
    ccze \
    libpcap0.8-dev \
    libuv1-dev && \
    rm -rf /var/lib/apt/lists/*

# Install Go
ENV GOLANG_VERSION 1.21.5
RUN wget https://golang.org/dl/go$GOLANG_VERSION.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go$GOLANG_VERSION.linux-amd64.tar.gz && \
    rm go$GOLANG_VERSION.linux-amd64.tar.gz

# Set Go environment variables
ENV GOPATH="$HOME/go-workspace"
ENV GOROOT="/usr/local/go"
ENV PATH="$PATH:$GOROOT/bin/:$GOPATH/bin"

# Install required Go tools

RUN go install github.com/harleo/knockknock@latest
RUN go install github.com/hahwul/dalfox/v2@latest
RUN go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest
RUN go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
RUN go install github.com/ffuf/ffuf/v2@latest
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install github.com/lc/gau/v2/cmd/gau@latest
RUN go install github.com/tomnomnom/waybackurls@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
RUN go install github.com/projectdiscovery/alterx/cmd/alterx@latest
RUN go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install github.com/tomnomnom/anew@latest
RUN go install github.com/tomnomnom/gf@latest
RUN go install github.com/ameenmaali/qsinject@latest
RUN go install github.com/tomnomnom/qsreplace@latest
RUN go install github.com/haccer/subjack@latest
RUN go install github.com/rverton/webanalyze/cmd/webanalyze@latest
RUN go install github.com/bp0lr/dmut@latest
RUN go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
RUN go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN go install github.com/lc/subjs@latest
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest

# Install Python dependencies
RUN pip3 install ansi2html
RUN pip3 install pyyaml
RUN pip3 install csvkit
RUN pip3 install shodan
RUN pip3 install pyyaml

RUN git clone https://github.com/mr-rizwan-syed/chomtesh.git
WORKDIR /app/chomtesh
RUN chmod + *.sh

RUN git clone https://github.com/codingo/Interlace.git ./MISC/Interlace && \
        pip3 install -r ./MISC/Interlace/requirements.txt && \
        cd ./MISC/Interlace/ && python3 setup.py install && cd -

RUN wget https://github.com/trufflesecurity/trufflehog/releases/download/v3.63.7/trufflehog_3.63.7_linux_amd64.tar.gz -P /tmp/ && \
        tar -xvf /tmp/trufflehog* -C /usr/local/bin/ && \
        chmod +x /usr/local/bin/trufflehog*

RUN git clone https://github.com/m4ll0k/SecretFinder.git ./MISC/SecretFinder
RUN pip3 install -r ./MISC/SecretFinder/requirements.txt
RUN git clone https://github.com/xnl-h4ck3r/waymore.git ./MISC/waymore
RUN git clone https://github.com/xnl-h4ck3r/xnLinkFinder.git ./MISC/xnLinkFinder
RUN git clone https://github.com/GerbenJavado/LinkFinder.git ./MISC/LinkFinder
RUN pip3 install -r ./MISC/LinkFinder/requirements.txt
RUN wget -q https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt -P /usr/share/dirb/wordlists/
RUN git clone https://github.com/projectdiscovery/fuzzing-templates.git ./MISC/fuzzing-templates/
RUN wget -q https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json -P ./MISC/
RUN wget -q https://raw.githubusercontent.com/rverton/webanalyze/master/technologies.json -P ./MISC/
RUN mkdir -p ~/.gf/ && cp ./MISC/excludeExt.json "$HOME/.gf/"

# SettingUp
RUN mv /usr/games/lolcat /usr/local/bin/
RUN nuclei -up && nuclei
RUN subfinder -up
RUN httpx -up
RUN naabu -up
RUN katana -up

# Define the default command to run when the container starts
CMD ["/bin/bash"]
