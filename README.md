# DoH Traffic Classifier using Machine Learning

This repository implements a DNS-over-HTTPS (DoH) traffic classification pipeline using machine learning models such as Multi-Layer Perceptron (MLP) and Random Forest. The goal is to detect and differentiate benign and malicious DoH traffic from PCAP files, with support for real-time inference using NEON-accelerated C code.

## Features

- PCAP parsing and flow-level feature extraction
- Support for DoH benign and malicious labeling
- Export of trained MLP model to C header for embedded inference
- Integration-ready with DPDK applications
- SIMD acceleration using ARM NEON intrinsics

## Folder Structure

