# JSON Web Signature 2020 Demo

Showcases the implementation of JSON Web Signature 2020 based on the test vectors in the spec:
https://www.w3.org/community/reports/credentials/CG-FINAL-lds-jws2020-20220721/#test-vectors

Signing the contents of _vc_0_ with _keypair_0_ should lead to the same proof section.

Run the demo via `npm install && npm start`. The output should be the below:

```
Expected:  eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..MJ5GwWRMsadCyLNXU_flgJtsS32584MydBxBuygps_cM0sbU3abTEOMyUvmLNcKOwOBE1MfDoB1_YY425W3sAg
Actual:    eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..MJ5GwWRMsadCyLNXU_flgJtsS32584MydBxBuygps_cM0sbU3abTEOMyUvmLNcKOwOBE1MfDoB1_YY425W3sAg
Done!
```
