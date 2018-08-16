
# LibIndy integration test suite

The suite is written by developers of the library. 
The suite comprises tests grouped into categories reflecting the functional sections of libindy API.
Most of tests require Indy pool running in the background. The simplest way to start it is to use standard indy docker configuration file 
to build and run the docker image with 4 nodes. The following environment variable instructs which  IP address will be used by test suite to connect to the pool:

```bash
TEST_POOL_IP
#e.g
TEST_POOL_IP=0.0.0.0
```

The integration test for selected category has to be run with the following command:
```bash
cargo test --test test-category -- --test-threads 1
```
Note that tests should be run with parallel execution disabled.

One can add the directive to produce more logging by adding the following environment variable to the command:
```bash
RUST_LOG=info cargo test ...
```


## Revocation tests

There are multiple revocation tests included into *anoncreds* test suite. They can be run by the following command:

```bash
cargo test --test anoncreds -- --test-threads=1
```

However, there is no test in the standard suite which employs one issuer  and multiple provers, where  credentials are issued first and revoked later.
The following test is added  to demonstrate how revocation technique works in this real case scenario:
 
 
 ```bash
 cargo test --test revocations -- --test-threads=1
 ```

The test creates 3 provers and issues 3 credentials, one for each prover. The first prover gets verified successfully.
The issuer revokes the credential of second prover then, so that the test expects the verification for second prover to fail.
Third prover  builds revocation state on the base of **updated** value of the accumulator 
( this value has to be submitted to the ledger by the issuer after revocation of the credential of second prover ). 
Third prover builds ( or rebuilds ) the proof using this new revocation state, and the proof will be validated successfully by the verifier.

### ledger txns

The test submits following txns to the ledger:

* new random NYM for the usser signed by TRUSTEE
* schema issued by the issuer
* credential definition with revocation supported, issued by the issuer
* revocation registry definition issued by the issuer

Note that the pool does not have to be restarted for the cleaning because every test run creates new NYM each time.

### work to be finished

Add transaction submission to update accumulator value in the ledger and to read it back using libindy API.
Currently the test uses the accumulator stored in the variable available in the scope of the code of test function.

