# Bulletproofs in Self Sovereign Ecosystem

The following library can be used to check if a number is greater than another using bulletproofs

This is based on https://github.com/omershlo/simple-bulletproof-js

## Pre-requisites

* Node.js
* Basic undrstanding of cryptography
* Knowledge of the working of Self sovereign Identity

## Steps to run
1. Generate the initial Pedersen Commitment for the value of x1 run ` node prover.js`.This would be signed by the issuer using his privatekey
you should see output like `Generated commitment,randomness and token`
2. Send the commitment token to the Holder, who in turn will pass it to a verifier
3. The Verifier will verify the signature on the token and decode it to recover the commitment. The Verifier will generate a commitment for the value of `a`
and subtract it from the original comitment and send it back to the holder.
run `node verifier.js`

Output should be 
`Verified token true
Recovered pedcomm commitment <EC Point x: 4fbaa4a7f27e11a76579bf6625df28731ce07859cb64a117e7b389df1e45c614 y: 24c7feb300efd2141456c9a7ecfa77ce35ffa2f9be2554a6e9f972aaf11e58b0>
Generated new commitment by subtracting prover commitment from verifier commitment`

4. The Holder generates the proof for the same using commitment from the verifier.  run `node prover.js proof`
output will be `proof generated`
5. The Verifier verifies this proof
`node verifier.js verify`

output will be 
`The provided proof that x>a is true`
