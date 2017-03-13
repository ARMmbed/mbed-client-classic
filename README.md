ARM mbed Client Classic
=======================

This repository contains ARM mbed Client Classic. You should not use this repo directly. This repo is the mbed
Client team's working area and we publish the official, tested versions as part of [mbed Client](https://github.com/ARMmbed/mbed-client).

If you want to see an example application - a better starting point would be the [mbed OS example client](https://github.com/ARMmbed/mbed-os-example-client).

## Running unit tests
1. Use the following command to clone required git repositories:

        make -f Makefile.test clone

2. After the cloning is done run the unit tests with:

        make -f Makefile.test test
    
### Pre-requisites for the unit tests
install the following tools:
- CppUTest
- XSL
- lcov
- gcovr
- Ninja 

To install these tools on Ubuntu run the following commands:

    sudo apt-get install cpputest
    sudo apt-get install xsltproc
    sudo apt-get install lcov
    sudo apt-get install gcovr
    sudo apt-get install ninja-build
