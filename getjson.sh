
baseurl='https://github.com/usnistgov/ACVP-Server/raw/refs/heads/master/gen-val/json-files'

set -euo pipefail


# Hash
mkdir -p json/hash
curl -fsSL "$baseurl/Ascon-Hash256-SP800-232/prompt.json" |
jq '[.testGroups[].tests[] | select(.len%8==0)]' >json/hash/simple.json

curl -fsSL "$baseurl/Ascon-Hash256-SP800-232/expectedResults.json" |
jq --argjson ids "$(jq -c '[.[].tcId]' <json/hash/simple.json)" '[.testGroups[].tests[] | select(IN(.tcId; $ids[]))]' >json/hash/want.json

# XOF
mkdir -p json/xof
curl -fsSL "$baseurl/Ascon-XOF128-SP800-232/prompt.json" |
jq '[.testGroups[].tests[] | select(.len%8==0 and .outLen%8==0)]' >json/xof/simple.json

curl -fsSL "$baseurl/Ascon-XOF128-SP800-232/expectedResults.json" |
jq --argjson ids "$(jq -c '[.[].tcId]' <json/xof/simple.json)" '[.testGroups[].tests[] | select(IN(.tcId; $ids[]))]' >json/xof/want.json

# CXOF
mkdir -p json/cxof
curl -fsSL "$baseurl/Ascon-CXOF128-SP800-232/prompt.json" |
jq '[.testGroups[].tests[] | select(.len%8==0 and .csLen%8==0 and .outLen%8==0)]' >json/cxof/simple.json

curl -fsSL "$baseurl/Ascon-CXOF128-SP800-232/expectedResults.json" |
jq --argjson ids "$(jq -c '[.[].tcId]' <json/cxof/simple.json)" '[.testGroups[].tests[] | select(IN(.tcId; $ids[]))]' >json/cxof/want.json


# AEAD
mkdir -p json/aead
curl -fsSL "$baseurl/Ascon-AEAD128-SP800-232/prompt.json" |
jq '[.testGroups[].tests[] | select(.payloadLen%8 == 0 and .adLen%8 == 0 and .tagLen%8==0)]' >json/aead/simple.json

curl -fsSL "$baseurl/Ascon-AEAD128-SP800-232/expectedResults.json" |
jq --argjson ids "$(jq -c '[.[].tcId]' <json/aead/simple.json)" '[.testGroups[].tests[] | select(IN(.tcId; $ids[]))]' >json/aead/want.json
