cd /home/jules/proj/code/go_libs/yggdrasil-go
PATH=/home/jules/go/bin:$PATH /home/jules/go/bin/gomobile bind -target android -androidapi 26 -tags mobile -o /app/app/libs/holowbark.aar -ldflags="-s -w -checklinkname=0 -extldflags=-Wl,-z,max-page-size=16384" ./contrib/mobile ./src/config ./contrib/awgmobile
cd /app
./gradlew assembleDebug
