# 🛡️ Amphikey: A Hybrid Post-Quantum Secure Communication Protocol

[![Language](https://img.shields.io/badge/Language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Build](https://img.shields.io/badge/Build-Passing-brightgreen.svg)]()

> A forward-secure communication protocol featuring a novel dual-mode design for both **provably authenticated** and **plausibly deniable** messaging, secured with a hybrid of classic and post-quantum cryptography.

---

## ✨ Core Features

* **Hybrid Crypto Agility**: Combines battle-tested classic cryptography (X25519) with NIST-standardized/selected post-quantum algorithms (ML-KEM, Raccoon, ASCON) for robust, long-term security.
* **Dual Operational Modes**:
    * 🔐 **Authenticated Mode**: For high-assurance scenarios like C12.22 smart meter data exchange where integrity and authenticity are paramount.
    * 🤫 **Deniable Mode**: For private messaging where participants can plausibly deny having ever communicated, protecting against coercion.
* **Lightweight & Performant**: Built in C and leverages ASCON, the NIST standard for lightweight cryptography, making it suitable for constrained environments.
* **Modular & Simple**: Comes with a clean Makefile for easy compilation of different components.

---

## 🏗️ Cryptographic Stack

The protocol's security is built upon a carefully selected suite of modern cryptographic primitives.

| Function                    | Algorithm                                                                                              | Type          |
| --------------------------- | ------------------------------------------------------------------------------------------------------ | ------------- |
| **Key Encapsulation** | `ML-KEM` (CRYSTALS-Kyber) + `X25519`                                                                     | Hybrid PQC/ECC |
| **Digital Signature** | `Raccoon`                                                                                              | PQC           |
| **Authenticated Encryption**| `ASCON`                                                                                                | Lightweight   |



---

## 🚀 Getting Started

Follow these steps to get the project compiled and running on your local machine.

### 1. Prerequisites

First, ensure you have the `gcc` compiler, standard build tools (`make`), and the `libsodium` library installed.

On **Debian/Ubuntu** systems, you can install them with:
```bash
sudo apt-get update
sudo apt-get install build-essential libsodium-dev
