const { expect } = require("chai");
const fs = require('fs');
const path = require('path');
const promisify = require('util').promisify;

const open = promisify(fs.open);
const read = promisify(fs.read);
const close = promisify(fs.close);
const strhead = "0x";
var data = new String();

//read all. the file contains verificationKey and proofdata
fs.readFile('foo', 'hex' , (err, data0) => {
  if (err) {
    console.error(err)
    return
  }
  data = data0
})


describe("plonk verifier contract", function () {
  it("just test", async function () {
    console.log("Hello");

    const [owner] = await ethers.getSigners();
    const addr = owner.address;
    
    const PlonkSingle = await ethers.getContractFactory("SingleVerifierWithDeserialize");
    const hardhatPlonkSingle = await PlonkSingle.deploy();

    //construct input data
    var vkdata = new Array();
    var proofdata = new Array();
    for (let index = 0; index < 30; index++) {
      let element = strhead.concat(data.slice(index*64, (index+1)*64));
      vkdata.push(element);
    }
    
    for (let index = 30; index < 62; index++) {
      let element = strhead.concat(data.slice(index*64, (index+1)*64));
      proofdata.push(element);
    }

    //test the proof
    var res = await hardhatPlonkSingle.test_interface(vkdata, proofdata);
    
    console.log(res);
    
  });
});