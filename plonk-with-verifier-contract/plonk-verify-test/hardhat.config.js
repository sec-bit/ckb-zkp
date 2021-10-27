require("@nomiclabs/hardhat-waffle");
require('hardhat-contract-sizer');
require("hardhat-gas-reporter");

task("ptest", "test sols").setAction(async () => {
    console.log("Hello, hh");
});

/**
 * @type import('hardhat/config').HardhatUserConfig
 */
 module.exports = {
    solidity: {
      version: "0.6.12",
      settings: {
        optimizer: {
          enabled: true,
          runs: 200
        }
      }
    },
    
    contractSizer: {
      alphaSort: true,
      runOnCompile: false,
      disambiguatePaths: false,
    },
    
  }