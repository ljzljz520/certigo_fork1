Set up a known-good certificate and an unclosed PEM block appended after it.

  $ awk '/cat > example-small-key.crt/{f=1;next} /^  > EOF/{f=0} f{sub(/^  > /,"");print}' "$TESTDIR/dump-small-key-to-json.t" > example-small-key.crt
  $ printf '\n-----BEGIN CERTIFICATE-----\nMIIBrokenTruncatedBlockWithoutEndLine\n' > tail.txt
  $ cat example-small-key.crt tail.txt > truncated.pem
  $ cat example-small-key.crt example-small-key.crt tail.txt > two-truncated.pem

dump emits the valid prefix certificate with a machine-readable failure in a
single JSON object, and exits 2.

  $ certigo dump --json truncated.pem > out.json; echo exit=$?
  error: file truncated.pem block 2 (byte offset 815): unclosed PEM block at end of input; input is truncated
  exit=2
  $ python3 -c 'import json; o=json.load(open("out.json")); i=o["parse_result"]["inputs"][0]; d=i["diagnostics"][0]; print(len(o["certificates"]), i["status"], d["kind"], d["source"]["block"], "error" in o, "chains" in o)'
  1 incomplete malformed_block 2 True False
  $ python3 -c 'import json; raw=open("out.json").read(); obj,n=json.JSONDecoder().raw_decode(raw); print(type(obj).__name__, len(raw[n:].strip()))'
  dict 0

Text mode prints the partial certificate on stdout and the error on stderr.

  $ certigo dump truncated.pem >/dev/null 2> err.txt; echo exit=$?
  exit=2
  $ grep -c 'unclosed PEM block' err.txt
  1

--first is a display filter only and must not hide the later parse failure.

  $ certigo dump --json --first two-truncated.pem > first.json; echo exit=$?
  error: file two-truncated.pem block 3 (byte offset 1629): unclosed PEM block at end of input; input is truncated
  exit=2
  $ python3 -c 'import json; o=json.load(open("first.json")); i=o["parse_result"]["inputs"][0]; print(len(o["certificates"]), len(i["certificates"]), i["status"])'
  1 2 incomplete

verify must not enter trust evaluation on an incomplete chain.

  $ certigo verify --json --name localhost two-truncated.pem > v.json; echo exit=$?
  exit=2
  $ python3 -c 'import json; o=json.load(open("v.json")); i=o["parse_result"]["inputs"][0]; print(i["status"], "chains" in o, "truncated" in o["error"])'
  incomplete False True
  $ certigo verify --name localhost two-truncated.pem >/dev/null 2> verr.txt; echo exit=$?
  exit=2
  $ grep -c '^error:' verr.txt
  1

A complete input still parses successfully.

  $ certigo dump --json example-small-key.crt > good.json; echo exit=$?
  exit=0
  $ python3 -c 'import json; o=json.load(open("good.json")); print(o["parse_result"]["inputs"][0]["status"], "error" in o)'
  complete False
