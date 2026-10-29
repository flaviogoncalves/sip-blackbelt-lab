INVITE sip:2002@lab.sip SIP/2.0
Via: SIP/2.0/UDP {src}:{port};branch={branch};rport
Max-Forwards: 70
From: <sip:2001@outside.example>;tag={tag}
To: <sip:2002@lab.sip>
Call-ID: {callid}@{src}
CSeq: 1 INVITE
Contact: <sip:2001@{src}:{port}>
Content-Length: {len}

v=0
o=2001 1 1 IN IP4 192.0.2.21
s=-
c=IN IP4 192.0.2.21
t=0 0
m=audio 30000 RTP/AVP 0
a=rtpmap:0 PCMU/8000
