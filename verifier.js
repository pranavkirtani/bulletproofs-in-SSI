const EC = require('elliptic').ec;

 

const ec = new EC('secp256k1');

var fs=require("fs");

function rangeBpVerifier(r0,r1,pedCom1,A,S,T1,T2,tauX,miu,tX,L,R,aTag,bTag){

 

  const crypto = require('crypto');

  const BigInteger = require('big-integer');

  const Consts = require('./consts');

  const utils = require('./utils_prover');

  const pickRandom = utils.pickRandom;

  const modulo = utils.modulo;

  const moduloPow = utils.moduloPow;

  const moduloAddq = utils.moduloAddq;

  const moduloSubq = utils.moduloSubq;

  const moduloMulq = utils.moduloMulq;

  const moduloMul = utils.moduloMul;

   var result10 = true;

 

  //creating g and h vectors:

  var gVector = [];

  var hVector = [];

  var gRand;

  var hRand;

  const H = utils.ec.g.mul((r0.toString(Consts.HEX)));

  let v = 0;

  while(v< Consts.upperBoundNumBits){

    gRand = utils.ec.g.x.fromRed().toString(16).concat(BigInteger(v).toString(Consts.HEX));

    hRand = H.x.fromRed().toString(16).concat(BigInteger(v).toString(Consts.HEX));

    gVector[v] = utils.ec.g.mul(modulo(BigInteger(crypto.createHash('sha256').update(gRand).digest('hex'),Consts.HEX),Consts.q).toString(Consts.HEX));

    hVector[v] = H.mul(modulo(BigInteger(crypto.createHash('sha256').update(hRand).digest('hex'),Consts.HEX),Consts.q).toString(Consts.HEX));

    v++;

  }

  const y_str = crypto.createHash('sha256').update(A.x.fromRed().toString(16).concat(S.x.fromRed().toString(16))).digest('hex');

  const z_str = crypto.createHash('sha256').update(A.x.fromRed().toString(16).concat(S.x.fromRed().toString(16).concat(y_str))).digest('hex');

  const y = BigInteger(y_str,Consts.HEX);

  const z = BigInteger(z_str,Consts.HEX);

 

  const zSquared = moduloPow(z,2,Consts.q);

  const zCubed = moduloPow(z,3,Consts.q);

  const zInv = z.modInv(Consts.q);

  const yi= [];

  var hiTag = [];

  const yiInv = [];

  let i=0;

  while(i<Consts.upperBoundNumBits){

    yi[i] = moduloPow(y,i,Consts.q);

    yiInv[i] = yi[i].modInv(Consts.q);

    hiTag[i] = hVector[i].mul(yiInv[i].toString(Consts.HEX));

    i++;

  }

 

  //k(y,z) + z<1,y>

  var t0 = BigInteger(0);

  var t0Part1;

  var t0Part2;

  var t0Part3;

  let j = 0;

  while(j< Consts.upperBoundNumBits){

    t0Part1 = modulo(modulo(z,Consts.q).multiply(modulo(yi[j],Consts.q)),Consts.q);

    t0Part2 = modulo(modulo(zSquared,Consts.q).multiply(modulo(yi[j],Consts.q)),Consts.q);

    t0Part3 = modulo(modulo(zCubed,Consts.q).multiply(moduloPow(BigInteger(2),j,Consts.q)),Consts.q);

    //t0 = modulo(modulo(modulo(t0.add(t0Part1),Consts.q).subtract(t0Part2),Consts.q).subtract(t0Part3),Consts.q);

    t0 = moduloSubq(moduloSubq(moduloAddq(t0,t0Part1),t0Part2),t0Part3);

    j++;

  }

 

  // fiat shamir challenge  line 50

  const concatStrings = T1.x.fromRed().toString(16).concat(T2.x.fromRed().toString(16)).concat(H.x.fromRed().toString(16));

  const temp = crypto.createHash('sha256').update(concatStrings).digest('hex');

  const xFiatShamirChall = modulo(BigInteger(temp,Consts.HEX),Consts.q);

  const xFiatShamirChallSquared = moduloPow(xFiatShamirChall,2,Consts.q);

  

  const eq63LeftSide = (utils.ec.g.mul(tX.toString(Consts.HEX))).add(H.mul(tauX.toString(Consts.HEX)));

  const eq63RightSide = (utils.ec.g.mul(t0.toString(Consts.HEX))).add(pedCom1.mul(zSquared.toString(Consts.HEX))).add(T1.mul(xFiatShamirChall.toString(Consts.HEX))).add(T2.mul(xFiatShamirChallSquared.toString(Consts.HEX)));

  if(eq63LeftSide.x.fromRed().toString(16)!=eq63RightSide.x.fromRed().toString(16)){result10=false;}

  if(eq63LeftSide.y.fromRed().toString(16)!=eq63RightSide.y.fromRed().toString(16)){result10=false;}

  //inner product proof:

  // P

  const transcript1 = tauX.toString(Consts.HEX).concat(miu.toString(Consts.HEX)).concat(tX.toString(Consts.HEX)); //33

  const NIchallenge1 = crypto.createHash('sha256').update(transcript1).digest('hex');

  const nic1 = BigInteger(NIchallenge1,Consts.HEX);

 

  //line 62 :


 var P = utils.ec.g.mul(nic1.toString(Consts.HEX)).mul(tX.toString(Consts.HEX)).add(H.mul(((Consts.q).subtract(miu)).toString(Consts.HEX)))

 

  P = P.add(A).add(S.mul(xFiatShamirChall.toString(Consts.HEX)));

 

  var hExponent = [];

  let k = 0;

  while(k< Consts.upperBoundNumBits){

    hExponent[k] = moduloAddq(moduloMulq(z,yi[k]),moduloMulq(zSquared,moduloPow(BigInteger(2),k,Consts.q)));

  P = P.add(gVector[k].mul(((Consts.q).subtract(z)).toString(Consts.HEX))).add(hiTag[k].mul(hExponent[k].toString(Consts.HEX)));

 

    k++;

  }

 

  var Ptag = P;

  const nPad = Consts.upperBoundNumBits;

  var nTag = nPad/2;

  var i2;

 

  var transcript;

  var NIchallenge;

  var x;

  var xinv;

  var xSquare;

  var xSquareInv;

  var gVectorTag= gVector;

    var hVectorTag = hiTag;

   j = 0;

  while(nTag>=1){

   

     transcript = L[j].x.fromRed().toString(16).concat(R[j].x.fromRed().toString(16)).concat(H.x.fromRed().toString(16));

     NIchallenge = crypto.createHash('sha256').update(transcript).digest('hex');

      x = BigInteger(NIchallenge,Consts.HEX);

      xinv = x.modInv(Consts.q);

    xSquare = moduloPow(x,2,Consts.q);

    xSquareInv = xSquare.modInv(Consts.q);

    gVector = gVectorTag;

    hiTag = hVectorTag;

     gVectorTag = [];

     hVectorTag = [];


  

    i2=0;

    while (i2<nTag){

    //  if(i2==nPad/2-1){//correction for padding g,h

    //    gVectorTag[i2] = (gVector[i2].mul(xinv.toString(Consts.HEX)));

    //    hVectorTag[i2] = (hiTag[i2].mul(x.toString(Consts.HEX)));

    //  }

    //  else{

 

        gVectorTag[i2] = (gVector[i2].mul(xinv.toString(Consts.HEX))).add(gVector[nTag+i2].mul(x.toString(Consts.HEX)));

        hVectorTag[i2] = (hiTag[i2].mul(x.toString(Consts.HEX))).add(hiTag[nTag+i2].mul(xinv.toString(Consts.HEX)));

   //  }

 

      i2++;

     }

 

    Ptag = (L[j].mul(xSquare.toString(Consts.HEX))).add(Ptag).add(R[j].mul(xSquareInv.toString(Consts.HEX)));

    j++;

    nTag= nTag/2;

  }

  const P1 = Ptag;

 

  const c = moduloMulq(aTag[0],bTag[0]);

  const finalVerify = (gVectorTag[0].mul(aTag[0].toString(Consts.HEX))).add(hVectorTag[0].mul(bTag[0].toString(Consts.HEX))).add(utils.ec.g.mul(nic1.toString(Consts.HEX)).mul(c.toString(Consts.HEX)));

 

  if(P1.x.fromRed().toString(16)!=finalVerify.x.fromRed().toString(16)){result10=false;}

  if(P1.y.fromRed().toString(16)!=finalVerify.y.fromRed().toString(16)){result10=false;}

 

  return result10;

}

const BigInteger = require('big-integer');

const Consts = require('./consts');

const utils = require('./utils_prover');

const { decodeToken, createUnsignedToken, SECP256K1Client, TokenSigner,TokenVerifier  } = require('jsontokens')

const pickRandom = utils.pickRandom;

const turnToBig= utils.turnToBig;

var randomness=JSON.parse(fs.readFileSync(__dirname+"/randomness.json",'utf-8'));

const r2=turnToBig(randomness.r2);

const r3=turnToBig(randomness.r3);

const r0=turnToBig(randomness.r0);

const r1=turnToBig(randomness.r1);

const r1_diff=r2.subtract(r0);

const r2_diff=r3.subtract(r1);

 

function generateVerifierCommitment(){

    var readData_ec=fs.readFileSync(__dirname+"/ec.json",'utf-8')

    readData_ec=JSON.parse(readData_ec);

    var ec_pub = { x: readData_ec[0], y:readData_ec[1] };

    var ec_key = ec.keyFromPublic(ec_pub, 'hex');

    utils.ec.g=ec_key.pub;

 

    const start=turnToBig(Math.pow(2,Consts.start))

    var token=fs.readFileSync(__dirname+"/file.json",'utf-8');

    const rawPublicKey = '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479'

    const verified = new TokenVerifier('ES256K', rawPublicKey).verify(token)

    console.log("Verified token",verified)

    const tokenData = decodeToken(token)

    const payload=JSON.parse(tokenData.payload)

    var pub = { x: payload.commitment[0], y:payload.commitment[1] };

    var key = ec.keyFromPublic(pub, 'hex');

    const newPedcom1=key.pub;

    console.log("Recovered pedcomm commitment",newPedcom1)

    const gstarA=utils.ec.g.mul(start.toString(Consts.HEX));

    const negGstarA=gstarA.neg(gstarA);

    const gr0tor1=utils.ec.g.mul((r0.multiply(r1)).toString(Consts.HEX));

    const gr2tor1=utils.ec.g.mul((r2.multiply(r1)).toString(Consts.HEX));

    const gr0tor3=utils.ec.g.mul((r0.multiply(r3).toString(Consts.HEX)))

    const sum_gr2tor1=gr2tor1.add(gr0tor3);

    const neg_sum_gr2tor1=sum_gr2tor1.neg(sum_gr2tor1)

    finalpedCom=newPedcom1.add(negGstarA).add(gr0tor1).add(neg_sum_gr2tor1)

    console.log("Generated new commitment by subtracting prover commitment from verifier commitment")

    const randomness_verifier={}

    randomness_verifier.r0=r0;

    randomness_verifier.r1=r1;

    fs.writeFileSync(__dirname+"/randomness_verifier.json",JSON.stringify(randomness_verifier));

    const json_data={"commitment":finalpedCom};

    const payload_final_pedcom = JSON.stringify(json_data)

    const data=fs.writeFileSync(__dirname+"/finalPedcom.json",payload_final_pedcom);

    console.log("Final Peddersen commitment and randomness saved to file")


}

function verifyProof(){

    var readData_ec=fs.readFileSync(__dirname+"/ec.json",'utf-8')

    readData_ec=JSON.parse(readData_ec);

    var ec_pub = { x: readData_ec[0], y:readData_ec[1] };

    var ec_key = ec.keyFromPublic(ec_pub, 'hex');

    utils.ec.g=ec_key.pub;

    var readData=fs.readFileSync(__dirname+"/proof.json",'utf-8');

    const readProof=JSON.parse(readData);

    var readData=fs.readFileSync(__dirname+"/finalPedcom.json",'utf-8');

   readData=JSON.parse(readData);

    const readCommitment=readData.commitment;

    var pub = { x: readCommitment[0], y:readCommitment[1] };

    var key = ec.keyFromPublic(pub, 'hex');

    const finalpedCom=key.pub;

 

    console.log("Generating A")

    pub = { x: readProof.A[0], y:readProof.A[1] };

    key = ec.keyFromPublic(pub, 'hex');

    const A=key.pub;

    console.log("Generated A")

 

    console.log("Generating S")

    pub = { x: readProof.S[0], y:readProof.S[1] };

    key = ec.keyFromPublic(pub, 'hex');

    const S=key.pub;

    console.log("Generated S")

 

    console.log("Generating T1")

    pub = { x: readProof.T1[0], y:readProof.T1[1] };

    key = ec.keyFromPublic(pub, 'hex');

    const T1=key.pub;

    console.log("Generated T1")

 

    console.log("Generating T2")

    pub = { x: readProof.T2[0], y:readProof.T2[1] };

    key = ec.keyFromPublic(pub, 'hex');

    const T2=key.pub;

    console.log("Generated T1")

    const tauX=turnToBig(readProof.tauX);

    const miu=turnToBig(readProof.miu);

    const tX=turnToBig(readProof.tX);

    const aTag=[turnToBig(readProof.aTag[0])]

    const bTag=[turnToBig(readProof.bTag[0])]

    console.log("Generated atag,btag,tx,taux,miu")

 

    console.log("Generating L")

    var L=[];

    for(let i=0;i<readProof.L.length;i++){

    pub = { x: readProof.L[i][0], y:readProof.L[i][1] };

    key = ec.keyFromPublic(pub, 'hex');

    L.push(key.pub);

 

    }

   

    console.log("Generated L")

 

     console.log("Generating R")

    var R=[];

    for(let i=0;i<readProof.R.length;i++){

    pub = { x: readProof.R[i][0], y:readProof.R[i][1] };

    key = ec.keyFromPublic(pub, 'hex');

    R.push(key.pub);

    }

    console.log("Generated R")

    const result11 = rangeBpVerifier(r1_diff,r2_diff,finalpedCom,A,S,T1,T2,tauX,miu,tX,L,R,aTag,bTag);

    console.log("The provided proof that x>a is",result11)

}

if(process.argv[2]=="verify"){

    verifyProof();

}

else {

    generateVerifierCommitment();

}

module.exports = {

  generateVerifierCommitment,verifyProof

};