# pcap_programming
---
`pcap` 라이브러리를 이용해 네트워크 패킷 정보를 출력하는 프로그램을 만들었습니다.<br/>
코드는 `ubuntu20.04` 버전에서 작성 되었으며,<br/> 
원활한 프로그램 작동을 위해선 `pcap` 라이브러리가 필요합니다.<br/>
<br/>
<br/>
---

## <설치 가이드 ↓>

<br/>
<br/>
1. `git clone https://github.com/fring-cloud/pcap_programming`
2. `gcc -o sniff sniff.c -lpcap`
<br/>
<br/>

`git` 명령어로 코드를 `clone` 받은 후, `gcc`로 컴파일 하면 끝입니다. 
`pcap`라이브러리만 있다면, 원활하게 작동 할 것입니다.
