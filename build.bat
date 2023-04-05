cd aes && go run aes.go
cd .. && go build -ldflags="-w -s -H windowsgui" ./main.go