#!/bin/bash

echo "==== allowed patterns ===="

curl -v "http://192.168.56.107:8080/dvwa/?id=1"
echo -e "\n"
sleep 1

curl -v "http://192.168.56.107:8080/dvwa/?search=hello"
echo -e "\n"
sleep 1

curl -v "http://192.168.56.107:8080/dvwa/?Spage=home"
echo -e "\n"
sleep 1


echo "==== XSS Test ===="
curl -v "http://192.168.56.107:8080/dvwa/login.php?username=<script>alert('HEY')</script>"
echo -e "\n"
sleep 1

echo "==== SQL Injection Test ===="
curl -v "http://192.168.56.107:8080/dvwa/?id=1%20UNION%20SELECT%20NULL,NULL--%20-"
echo -e "\n"
sleep 1

echo "==== Path Traversal Test ===="
curl -v "http://192.168.56.107:8080/dvwa/?id=../../../../etc/passwd"
echo -e "\n"
sleep 1

echo "==== Command Injection Test ===="
curl -v "http://192.168.56.107:8080/dvwa/?id=1%20||%20cat%20/etc/passwd"
echo -e "\n"
sleep 1

echo "==== Trajon/Backdoor Test ===="
curl -v "http://192.168.56.107:8080/dvwa/?data=base64_decode('AAAA')"
echo -e "\n"
sleep 1

echo "==== Buffer Overflow signature (6000 characters) ===="
curl -v "http://192.168.56.107:8080/dvwa/?q=$(printf 'A%.0s' {1..6000})"
echo -e "\n"
sleep 1

echo "==== DB Delay ===="
curl -v "http://192.168.56.107:8080/dvwa/?id=waitfor%20delay('00:00:05')"
echo -e "\n"
sleep 1

echo "==== Honeypot triggered ===="
curl -v "http://192.168.56.107:8080/dvwa/?honeypot=1"
echo -e "\n"
sleep 1

echo "==== potintial patterns ===="

curl -v "http://192.168.56.107:8080/dvwa/vulnerabilities/xss_r/?name=<img%20src=x%20onerror=alert(1)>"
echo -e "\n"
sleep 1

curl -v "http://192.168.56.107:8080/dvwa/vulnerabilities/xss_r/?name=<img%20src=x%20onerror=alert(1)>--test"
echo -e "\n"
sleep 1



echo "==== DONE ===="

