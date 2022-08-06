#!/bin/bash

sudo openssl genrsa -out responder.key 2048

sudo openssl req -new -x509 -days 3650 -key responder.key -out responder.crt -subj "/"
