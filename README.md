# Password Strength Analysis (C / CUDA)

Educational project focused on analyzing password strength using brute-force techniques and comparing CPU vs GPU performance.

## Overview

Password strength reflects how resistant a password is to guessing or brute-force attacks :contentReference[oaicite:0]{index=0}.  
This project demonstrates how computational power and parallel processing affect the time required to brute-force passwords.

The goal of this project is to:
- understand how password complexity affects security
- compare CPU and GPU performance
- explore parallel computing with CUDA

---

## Features

- Brute-force password generation
- CPU implementation (C)
- GPU implementation (CUDA)
- Parallel computation using GPU threads
- Performance comparison (CPU vs GPU)
- Analysis of password length and complexity impact

---

## Tech Stack

- C
- CUDA
- Parallel Computing

---

## How It Works

The program generates combinations of characters and attempts to match a target password.

Two implementations are provided:

### CPU version
- Sequential brute-force
- Limited by single-thread performance

### GPU version
- Parallel brute-force using CUDA
- Thousands of threads running simultaneously
- Significant speed improvement compared to CPU



