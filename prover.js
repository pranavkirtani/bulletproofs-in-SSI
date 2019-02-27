const EC = require('elliptic').ec;

const defineCurve = require('elliptic').curves;

const ec = new EC('secp256k1');

var fs=require("fs");

const utils = require('./utils_prover');

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

  console.log("utils.ec.g in verifier",utils.ec.g)

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

 

  if(eq63LeftSide.x.fromRed().toString(16)!=eq63RightSide.x.fromRed().toString(16)){result10=false; }

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

  if(P1.y.fromRed().toString(16)!=finalVerify.y.fromRed().toString(16)){result10=false; }

 

  return result10;

}

function rangeBpProver(x1,pedCom1,r0,r1){

 

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




  const aL = [];

  const aR = [];

  const SL = [];

  const SR = [];

 

  const alpha = pickRandom(Consts.q);

  const rho = pickRandom(Consts.q);

//   const alpha = turnToBig(7)

//   const rho = turnToBig(8)

 

  const gVector = [];

  const hVector = [];

  var gRand;

  var hRand;

  console.log("utils.ec.g in prover",utils.ec.g)

  const H = utils.ec.g.mul((r0.toString(Consts.HEX)));

  let v = 0;

  while(v< Consts.upperBoundNumBits){

    gRand = utils.ec.g.x.fromRed().toString(16).concat(BigInteger(v).toString(Consts.HEX));

    hRand = H.x.fromRed().toString(16).concat(BigInteger(v).toString(Consts.HEX));

    gVector[v] = utils.ec.g.mul(modulo(BigInteger(crypto.createHash('sha256').update(gRand).digest('hex'),Consts.HEX),Consts.q).toString(Consts.HEX));

    hVector[v] = H.mul(modulo(BigInteger(crypto.createHash('sha256').update(hRand).digest('hex'),Consts.HEX),Consts.q).toString(Consts.HEX));

    v++;

  }

 

  var A  = H.mul(alpha.toString(Consts.HEX));

  var S = H.mul(rho.toString(Consts.HEX));

  let i = 0;

  while(i< Consts.upperBoundNumBits){

    aL[i]=x1.shiftRight(i).mod(2).and(BigInteger(1));

    aR[i]= moduloSubq(aL[i],BigInteger(1));

    A = A.add(gVector[i].mul(aL[i].toString(Consts.HEX))).add(hVector[i].mul(aR[i].toString(Consts.HEX)));

  

    SL[i] = pickRandom(Consts.q);

    SR[i] = pickRandom(Consts.q);

    // SL[i] = turnToBig(9)

    // SR[i] = turnToBig(10)

    S = (S).add(gVector[i].mul(SL[i].toString(Consts.HEX))).add(hVector[i].mul(SR[i].toString(Consts.HEX)));

  

    i++;

  }

 

  const y_str = crypto.createHash('sha256').update(A.x.fromRed().toString(16).concat(S.x.fromRed().toString(16))).digest('hex');

  const z_str = crypto.createHash('sha256').update(A.x.fromRed().toString(16).concat(S.x.fromRed().toString(16).concat(y_str))).digest('hex');

  const y = BigInteger(y_str,Consts.HEX);

  const z = BigInteger(z_str,Consts.HEX);

 

  const zSquared = moduloPow(z,2,Consts.q);

  const zCubed = moduloPow(z,3,Consts.q);

  var t0  = modulo(modulo(zSquared,Consts.q).multiply(modulo(x1,Consts.q)),Consts.q);

  var t0Part1;

  var t0Part2;

  var t0Part3;

  var t1 = BigInteger(0);

  var t1Part1;

  var t1Part2;

  var t1Part3;

  var t1Part4;

  var t1Part5;

  var t1Part6;

  var t1Part7;

  var t1Part8;

  var t2 = BigInteger(0);

  var t2Part1;

  var t2Part2;

  var t2Part3;

  var yi = [];

  let s = 0;

  while(s< Consts.upperBoundNumBits){

    yi[s] = moduloPow(y,s,Consts.q);

    t0Part1 = modulo(modulo(z,Consts.q).multiply(modulo(yi[s],Consts.q)),Consts.q);

    t0Part2 = modulo(modulo(zSquared,Consts.q).multiply(modulo(yi[s],Consts.q)),Consts.q);

    t0Part3 = modulo(modulo(zCubed,Consts.q).multiply(moduloPow(BigInteger(2),s,Consts.q)),Consts.q);

    t0 = moduloSubq(moduloSubq(moduloAddq(t0,t0Part1),t0Part2),t0Part3);

    //t0 = modulo(modulo(modulo(t0.add(t0Part1),Consts.q).subtract(t0Part2),Consts.q).subtract(t0Part3),Consts.q);

    //t0 = t0.add(z.multiply(yi[i]).add(zSquared.multiply(yi[i]).multiply(-1)).add(zCubed.multiply(BigInteger(2).pow(i)).multiply(-1)));

    t1Part1 = modulo(aR[s].add(z),Consts.q);

    t1Part2 = modulo(modulo(t1Part1,Consts.q).multiply(modulo(yi[s],Consts.q)),Consts.q);

    t1Part3 = modulo(modulo(SL[s],Consts.q).multiply(modulo(t1Part2,Consts.q)),Consts.q);

    t1Part4 = moduloSubq(aL[s],z);

    //t1Part4 = modulo(aL[i].subtract(z),Consts.q);

    t1Part5 = modulo(modulo(SR[s],Consts.q).multiply(modulo(yi[s],Consts.q)),Consts.q);

    t1Part6 = modulo(modulo(t1Part4,Consts.q).multiply(modulo(t1Part5,Consts.q)),Consts.q);

    t1Part7 = modulo(modulo(zSquared,Consts.q).multiply(moduloPow(BigInteger(2),s,Consts.q)),Consts.q);

    t1Part8 = moduloMulq(t1Part7,SL[s]);

    t1 = moduloAddq(moduloAddq(moduloAddq(t1,t1Part3),t1Part6),t1Part8);

   // t1 = modulo(modulo(t1.add(t1Part3),Consts.q).add(t1Part6),Consts.q);

    t2Part1 = modulo(modulo(SR[s],Consts.q).multiply(modulo(yi[s],Consts.q)),Consts.q);

    t2Part2 = modulo(modulo(SL[s],Consts.q).multiply(modulo(t2Part1,Consts.q)),Consts.q);

    t2 = modulo(t2.add(t2Part2),Consts.q);

    //t1 = t1.add((SL[i].multiply((aR[i].add(z)).multiply(yi[i]))).add((aL[i].subtract(z)).multiply(SR[i].add(yi[i]))));

    //t2 = t2.add(SL[i].multiply(SR[i].multiply(yi[i])));

    s++;

  }

  const tau1 = pickRandom(Consts.q);

  const tau2 = pickRandom(Consts.q);

//   const tau1 = turnToBig(11)

//   const tau2 = turnToBig(12)

  const T1 = utils.ec.g.mul(t1.toString(Consts.HEX)).add(H.mul(tau1.toString(Consts.HEX)));

  const T2 = utils.ec.g.mul(t2.toString(Consts.HEX)).add(H.mul(tau2.toString(Consts.HEX)));

 

  //fiat shamir for verifier challenge:

  const concatStrings = T1.x.fromRed().toString(16).concat(T2.x.fromRed().toString(16)).concat(H.x.fromRed().toString(16));

  const temp = crypto.createHash('sha256').update(concatStrings).digest('hex');

  const xFiatShamirChall = modulo(BigInteger(temp,Consts.HEX),Consts.q);

  const xFiatShamirChallSquared = moduloPow(xFiatShamirChall, 2,Consts.q);

  //(A * B) mod C = (A mod C * B mod C) mod C

  const tauPart1 = modulo(modulo(tau1,Consts.q).multiply(modulo(xFiatShamirChall,Consts.q)),Consts.q);

  const tauPart2 = modulo(modulo(tau2,Consts.q).multiply(xFiatShamirChallSquared),Consts.q);

  const tauPart3 = modulo(modulo(zSquared,Consts.q).multiply(modulo(r1,Consts.q)),Consts.q);

  const tauX = modulo(modulo(tauPart1.add(tauPart2),Consts.q).add(tauPart3),Consts.q);

  const miuPart1 = modulo(modulo(rho,Consts.q).multiply(modulo(xFiatShamirChall,Consts.q)),Consts.q);

  const miu =  modulo(alpha.add(miuPart1),Consts.q);

  var Lp = [];

  var LpPart1;

  var Rp = [];

  var RpPart1;

  var RpPart2;

  var RpPart3;

  var RpPart4;

  var tX = BigInteger(0);

  var tXPart1;

  var j = 0;

  while(j< Consts.upperBoundNumBits){

    //(A + B) mod C = (A mod C + B mod C) mod C

    LpPart1 = modulo(modulo(SL[j],Consts.q).multiply(modulo(xFiatShamirChall,Consts.q)),Consts.q);

    //Lp[j] = modulo(modulo(aL[j].subtract(z),Consts.q).add(LpPart1),Consts.q);

    Lp[j] = moduloAddq(moduloSubq(aL[j],z),LpPart1);   

    //Lp[j] = aL[j].subtract(z).add(SL[j].multiply(xFiatShamirChall));

    RpPart1 = modulo(modulo(SR[j],Consts.q).multiply(modulo(xFiatShamirChall,Consts.q)),Consts.q);

    RpPart2 = modulo(modulo(zSquared,Consts.q).multiply(moduloPow(BigInteger(2),j,Consts.q)),Consts.q);

    RpPart3 = modulo(modulo(aR[j].add(z),Consts.q).add(RpPart1),Consts.q);

    RpPart4 = modulo(modulo(yi[j],Consts.q).multiply(modulo(RpPart3,Consts.q)),Consts.q);

    Rp[j] = modulo(RpPart4.add(RpPart2),Consts.q);

    //Rp[j] = (yi[j].multiply(aR[j].add(z).add(SR[j].multiply(xFiatShamirChall)))).add(zSquared.multiply(BigInteger(2).pow(j)));

    tXPart1 = modulo(modulo(Lp[j],Consts.q).multiply(modulo(Rp[j],Consts.q)),Consts.q);

    tX = modulo(tX.add(tXPart1),Consts.q);

    //tX = tX.add(Lp[j].multiply(Rp[j]));

    j++;

  }

 

  const transcript1 = tauX.toString(Consts.HEX).concat(miu.toString(Consts.HEX)).concat(tX.toString(Consts.HEX));

  const NIchallenge1 = crypto.createHash('sha256').update(transcript1).digest('hex');

  const nic1 = modulo(BigInteger(NIchallenge1,Consts.HEX),Consts.q);

 

  let k=0;

 

  var P = utils.ec.g.mul(nic1.toString(Consts.HEX)).mul(tX.toString(Consts.HEX));

  //var P = utils.ec.g.mul(0);

 

  var hiTag = [];

  var yiInv = [];

  while(k<Consts.upperBoundNumBits){

    yi[k] = moduloPow(y,k,Consts.q);

    yiInv[k] = yi[k].modInv(Consts.q);

    hiTag[k] = hVector[k].mul(yiInv[k].toString(Consts.HEX));

    P = P.add(gVector[k].mul(Lp[k].toString(Consts.HEX))).add(hiTag[k].mul(Rp[k].toString(Consts.HEX)));

    k++;

  }

 

  //Lp[Consts.upperBoundNumBits] = BigInteger(0); //padding

  //Rp[Consts.upperBoundNumBits] = BigInteger(0); //padding

  const {L,R,aTag,bTag}= innerProductArgument(nic1,P, Lp,Rp,H,hiTag,gVector);

 

  return {A,S,T1,T2,tauX,miu,tX,L,R,aTag,bTag};

 

}

 

function innerProductArgument(nic1,P, Lp,Rp,H,hiTag,gVector){

 

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

 

 var Ptag = P;

  const nPad = Consts.upperBoundNumBits;

  var nTag = nPad/2;

  var i1;

  var i2;

  var cL=BigInteger(1);

  var cR=BigInteger(0);

  var cLi;

  var cRi;

  const L = []; //init

  const R = []; //init

  var transcript;

  var NIchallenge;

  var x;

  var xinv;

  var xSquare;

  var xSquareInv;

  var gVectorTag= gVector;

    var hVectorTag = hiTag;

    var aTag = Lp;

    var bTag =Rp;

    var a ;

    var b;

  //  aTag[Consts.upperBoundNumBits] = BigInteger(0); //padding

  //  bTag[Consts.upperBoundNumBits] = BigInteger(0);// padding

  var j = 0;

  while(nTag>=1){

   L[j]= utils.ec.g.mul('0'); //init

   R[j]=utils.ec.g.mul('0');  //init

    cL=BigInteger(0);

    cR=BigInteger(0);

    i1=0;

 

    while (i1<nTag){

 

      cLi= modulo(modulo(aTag[i1],Consts.q).multiply(modulo(bTag[nTag+i1],Consts.q)),Consts.q);

      cRi = modulo(modulo(aTag[nTag+i1],Consts.q).multiply(modulo(bTag[i1],Consts.q)),Consts.q);

      cL = moduloAddq(cL,cLi);

      cR = moduloAddq(cR,cRi);

 

        L[j] = L[j].add(gVectorTag[nTag+i1].mul(aTag[i1].toString(Consts.HEX))).add(hVectorTag[i1].mul(bTag[nTag+i1].toString(Consts.HEX)));

        R[j] = R[j].add(gVectorTag[i1].mul(aTag[nTag+i1].toString(Consts.HEX))).add(hVectorTag[nTag+i1].mul(bTag[i1].toString(Consts.HEX)));

 

      i1++;

    }

 

    L[j] = L[j].add(utils.ec.g.mul(cL.toString(Consts.HEX)).mul(nic1.toString(Consts.HEX)));

    R[j] = R[j].add(utils.ec.g.mul(cR.toString(Consts.HEX)).mul(nic1.toString(Consts.HEX)));

   

     transcript = L[j].x.fromRed().toString(16).concat(R[j].x.fromRed().toString(16)).concat(H.x.fromRed().toString(16));

     NIchallenge = crypto.createHash('sha256').update(transcript).digest('hex');

      x = modulo(BigInteger(NIchallenge,Consts.HEX),Consts.q);

    //  //console.log(x)

      xinv = x.modInv(Consts.q);

    xSquare = moduloPow(x,2,Consts.q);

    xSquareInv = xSquare.modInv(Consts.q);

    xSquareInv = moduloPow(xinv,2,Consts.q);

    gVector = gVectorTag;

    hiTag = hVectorTag;

     gVectorTag = [];

     hVectorTag = [];

     a = aTag;

     b= bTag;

     aTag = [];

     bTag =[];

 

    i2=0;

    while (i2<nTag){

    //  if(i2==nPad/2-1){//correction for padding g,h

    //    gVectorTag[i2] = (gVector[i2].mul(xinv.toString(Consts.HEX)));

    //    hVectorTag[i2] = (hiTag[i2].mul(x.toString(Consts.HEX)));

    //  }

    //  else{

 

        gVectorTag[i2] = (gVector[i2].mul(xinv.toString(Consts.HEX))).add(gVector[nTag+i2].mul(x.toString(Consts.HEX)));

        hVectorTag[i2] = (hiTag[i2].mul(x.toString(Consts.HEX))).add(hiTag[nTag+i2].mul(xinv.toString(Consts.HEX)));

    // }

      aTag[i2] = modulo(modulo(a[i2].multiply(x),Consts.q).add(modulo(a[nTag+i2].multiply(xinv),Consts.q)),Consts.q);

      bTag[i2] = modulo(modulo(b[i2].multiply(xinv),Consts.q).add(modulo(b[nTag+i2].multiply(x),Consts.q)),Consts.q);

      i2++;

     }

 

    Ptag = (L[j].mul(xSquare.toString(Consts.HEX))).add(Ptag).add(R[j].mul(xSquareInv.toString(Consts.HEX)));

    j++;

    nTag= nTag/2;

  }




  return {L,R,aTag,bTag};

}

 

function exportUtils(){

       

        return utils.ec.g;

}

const { decodeToken, createUnsignedToken, SECP256K1Client, TokenSigner,TokenVerifier  } = require('jsontokens')

const pickRandom= utils.pickRandom;

const BigInteger = require('big-integer');

const Consts = require('./consts');

const turnToBig= utils.turnToBig;

const x1 = turnToBig(7)

const start=turnToBig(Math.pow(2,Consts.start))

const difference=x1.subtract(start);

const r0 = turnToBig(100)

const r1 = turnToBig(201)

const r2 =turnToBig(900)

const r3 = turnToBig(400)

const r1_diff=r2.subtract(r0);

const r2_diff=r3.subtract(r1);

function generateCommitment(){

    ////console.log("utils.ec",utils.ec)

    const data_ec=fs.writeFileSync(__dirname+"/ec.json",JSON.stringify(utils.ec.g));

    const pedCom1 =utils.ec.g.mul(x1.toString(Consts.HEX)).add(utils.ec.g.mul((r2.multiply(r3)).toString(Consts.HEX)));

    var json_data={"commitment":pedCom1};

    const tokenPayload = JSON.stringify(json_data)

    const rawPrivateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'

    var token = new TokenSigner('ES256K', rawPrivateKey).sign(tokenPayload)

    var data=fs.writeFileSync(__dirname+"/file.json",token);

    const randomness={}

    randomness.r2=r2;

    randomness.r3=r3;

    randomness.r0=r0;

    randomness.r1=r1;

    fs.writeFileSync(__dirname+"/randomness.json",JSON.stringify(randomness));

    console.log("Generated commitment,randomness and token");

 

}

function generateProof(){

    var readData_ec=fs.readFileSync(__dirname+"/ec.json",'utf-8')

    readData_ec=JSON.parse(readData_ec);

    var ec_pub = { x: readData_ec[0], y:readData_ec[1] };

    var ec_key = ec.keyFromPublic(ec_pub, 'hex');

    utils.ec.g=ec_key.pub;

    //console.log("r1_diff",r1_diff,"r2_diff",r2_diff);

    var readData=fs.readFileSync(__dirname+"/finalPedcom.json",'utf-8');

    readData=JSON.parse(readData);

    var readCommitment=readData.commitment;

    var pub = { x: readCommitment[0], y:readCommitment[1] };

    var key = ec.keyFromPublic(pub, 'hex');

    var finalpedCom=key.pub;

    //console.log("difference",difference);

    const proof=rangeBpProver(difference,finalpedCom,r1_diff,r2_diff);

    //console.log("finalpedCom",finalpedCom);

    const data=fs.writeFileSync(__dirname+"/proof.json",JSON.stringify(proof));

    console.log("proof generated");

    //verifier code

  

}

if(process.argv[2]=="proof"){

    generateProof();

}

else {

    generateCommitment();

  //single()

}

 

function single(){

 

    generateCommitment()

 

    generateProof()

  

 

}