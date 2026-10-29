OPTIONS sip:2002@lab.sip SIP/2.0
Via: SIP/2.0/UDP {src}:{port};branch={branch};rport
Max-Forwards: 70
From: <sip:2001@outside.example>;tag={tag}
To: <sip:2002@lab.sip>
Call-ID: {callid}@{src}
CSeq: 1 OPTIONS
Contact: <sip:2001@{src}:{port}>
Content-Length: 50

