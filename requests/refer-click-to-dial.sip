REFER sip:2001@192.0.2.21:5060 SIP/2.0
Via: SIP/2.0/UDP {src}:{port};branch={branch};rport
Max-Forwards: 70
From: <sip:pc-2001@lab.sip>;tag={tag}
To: <sip:2001@lab.sip>
Call-ID: {callid}@{src}
CSeq: 1 REFER
Contact: <sip:pc-2001@{src}:{port}>
Refer-To: <sip:2002@lab.sip>
Refer-Sub: false
Content-Length: 0
