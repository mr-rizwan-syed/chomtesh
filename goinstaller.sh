#!/bin/bash

GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
NC=`tput sgr0`

SHELL_TYPE=$(basename "$SHELL")

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

gowebsite=https://go.dev/dl/
golatest=$(curl -s https://go.dev/dl/ | grep -o '<a class="download downloadBox" href="[^"]*' | grep linux-amd64 | cut -d '"' -f 4 | cut -d / -f 3)
downloadgo=$gowebsite$golatest

goinstaller(){
	echo "${YELLOW}[*] Installing GO ${NC}"
        wget $downloadgo -P /tmp/
  	[ ! -d "/usr/local/go" ] && tar -C /usr/local/ -xzf /tmp/$golatest
	rm /tmp/$golatest
	echo $shellrc
        echo 'export GOPATH=/root/go-workspace' >> $shellrc
        echo 'export GOROOT=/usr/local/go' >> $shellrc
        echo 'PATH=$PATH:$GOROOT/bin/:$GOPATH/bin' >> $shellrc
	exec $SHELL
}

if ! command_exists go; then
	if [ "$SHELL_TYPE" = "bash" ]; then
		shellrc=~/.bashrc
		echo $shellrc
		goinstaller
		command_exists go && echo -e "${GREEN}Go Installed Successfully !!!${NC}"
	elif [ "$SHELL_TYPE" = "zsh" ]; then
		shellrc=~/.zshrc
		echo $shellrc
		goinstaller
		command_exists go && echo -e "${GREEN}Go Installed Successfully !!!${NC}"
	else
    		echo "Unsupported shell type: $SHELL_TYPE"
	fi
elif command_exists go; then
	echo "${GREEN}[*] GO Already Installed ${NC}"
fi
