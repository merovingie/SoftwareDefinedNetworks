#!/usr/bin/env bash

#set interfaces
#switch 3
curl -X POST -d '{"address": "172.16.20.1/24"}' http://localhost:8080/router/0000000000000003/2
curl -X POST -d '{"address": "172.16.20.1/24"}' http://localhost:8080/router/0000000000000003/110
curl -X POST -d '{"address": "10.10.10.3/24"}' http://localhost:8080/router/0000000000000003/2
curl -X POST -d '{"address": "10.10.10.3/24"}' http://localhost:8080/router/0000000000000003/110
sleep 3

#switch 2
curl -X POST -d '{"address": "192.168.30.1/24"}' http://localhost:8080/router/0000000000000002/2
curl -X POST -d '{"address": "192.168.30.1/24"}' http://localhost:8080/router/0000000000000002/110
curl -X POST -d '{"address": "10.10.10.2/24"}' http://localhost:8080/router/0000000000000002/2
curl -X POST -d '{"address": "10.10.10.2/24"}' http://localhost:8080/router/0000000000000002/110
sleep 3

#switch 1
curl -X POST -d '{"address": "172.16.10.1/24"}' http://localhost:8080/router/0000000000000001/2
curl -X POST -d '{"address": "172.16.10.1/24"}' http://localhost:8080/router/0000000000000001/110
curl -X POST -d '{"address": "10.10.10.1/24"}' http://localhost:8080/router/0000000000000001/2
curl -X POST -d '{"address": "10.10.10.1/24"}' http://localhost:8080/router/0000000000000001/110
sleep 3

#set Default Route
#gateway router 1
curl -X POST -d '{"gateway": "10.10.10.2"}' http://localhost:8080/router/0000000000000001/2
curl -X POST -d '{"gateway": "10.10.10.2"}' http://localhost:8080/router/0000000000000001/110
sleep 3

#gateway router 2
curl -X POST -d '{"gateway": "10.10.10.1"}' http://localhost:8080/router/0000000000000002/2
curl -X POST -d '{"gateway": "10.10.10.1"}' http://localhost:8080/router/0000000000000002/110
sleep 3

#gateway router 3
curl -X POST -d '{"gateway": "10.10.10.2"}' http://localhost:8080/router/0000000000000003/2
curl -X POST -d '{"gateway": "10.10.10.2"}' http://localhost:8080/router/0000000000000003/110
sleep 3

#set static routes
curl -X POST -d '{"destination": "172.16.20.0/24", "gateway": "10.10.10.3"}' http://localhost:8080/router/0000000000000002/2
sleep 3

#requested route
curl -X POST -d '{"destination": "172.16.20.0/24", "gateway": "10.10.10.3"}' http://localhost:8080/router/0000000000000002/110
sleep 3
