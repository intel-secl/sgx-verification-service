#!/bin/bash
unset http_proxy
unset https_proxy

quote_content=$( cat ./tmp/sgx_ecdsa_quote_dump.txt )

curl -vvv --insecure -H "Content-Type: application/json" -X POST "https://localhost:12000/svs/v1/verifyQuote" --data "{ \"quote\": \"$quote_content\"}"
