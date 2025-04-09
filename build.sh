#!/bin/bash

export VERSION="v0.0.5"

rm -rf target
mkdir -p target

env GOOS=darwin GOARCH=amd64 go build -o ./target/openunison-cli-$VERSION-macos .
env GOOS=linux GOARCH=amd64 go build -o ./target/openunison-cli-$VERSION-linux .
env GOOS=windows GOARCH=amd64 go build -o ./target/openunison-cli-$VERSION-win.exe .

mkdir target/darwin
cp ./target/openunison-cli-$VERSION-macos target/darwin/openunison-cli
chmod +x target/darwin/openunison-cli
cp LICENSE target/darwin/
cd target/darwin/
zip openunison-cli-$VERSION-macos.zip ./openunison-cli LICENSE
cd ../../
mv target/darwin/openunison-cli-$VERSION-macos.zip target/
rm -rf target/darwin

mkdir target/linux
cp ./target/openunison-cli-$VERSION-linux target/linux/openunison-cli
chmod +x target/linux/openunison-cli
cp LICENSE target/linux/
cd target/linux/
zip openunison-cli-$VERSION-linux.zip ./openunison-cli LICENSE
cd ../../
mv target/linux/openunison-cli-$VERSION-linux.zip target/
rm -rf target/linux

mkdir target/win
cp ./target/openunison-cli-$VERSION-win.exe target/win/openunison-cli.exe
cp LICENSE target/win/
cd target/win/
zip openunison-cli-$VERSION-win.zip ./openunison-cli.exe ./LICENSE
cd ../../
mv target/win/openunison-cli-$VERSION-win.zip target/
rm -rf target/win





export MACOS_SHA256=$(sha256sum ./target/openunison-cli-$VERSION-macos.zip | awk '{print $1}')
export LINUX_SHA256=$(sha256sum ./target/openunison-cli-$VERSION-linux.zip | awk '{print $1}')
export WIN_SHA256=$(sha256sum ./target/openunison-cli-$VERSION-win.zip | awk '{print $1}')

cat openunison-cli.yaml | sed "s/_VERSION_/$VERSION/g" | sed "s/_MAC_SHA_/$MACOS_SHA256/g" | sed "s/_LINUX_SHA_/$LINUX_SHA256/g" | sed "s/_WIN_SHA_/$WIN_SHA256/g" | sed "s/_OU_CLI_DIR_/$1/g"  > target/openunison-cli.yaml

aws s3 sync ./target/ s3://tremolosecurity-maven/repository/$1/



