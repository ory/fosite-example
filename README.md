# ORY Fosite Example Server

[![Build Status](https://travis-ci.org/ory/fosite-example.svg?branch=master)](https://travis-ci.org/ory/fosite-example)

ORY Fosite is the security first OAuth2 & OpenID Connect framework for Go. Built simple, powerful and extensible. This repository contains an exemplary http server using ORY Fosite for serving OAuth2 requests.

## Install and run

The Fosite example server requires [`go@1.13` or higher installed](https://golang.org/dl/) as it uses go modules for dependency management. 
Once installed, run the demo:

```
$ go get -d github.com/ory/fosite-example
$ cd $GOPATH/src/github.com/ory/fosite-example
$ go run main.go
```
