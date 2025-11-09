# Encrypted Notes Vault

A command-line encrypted notes application for secure local storage. Uses AES-256-GCM encryption with password-based key derivation.

## Overview

This project implements a simple vault for storing encrypted notes locally. All encryption happens on your machine and no data is transmitted over the network. Built to learn practical cryptography and secure storage patterns.

## Features

- Password-protected vault with PBKDF2 key derivation (100,000 iterations)
- AES-256-GCM authenticated encryption for individual notes
- SQLite database for local storage
- Search functionality by note title
- Secure deletion with confirmation prompts
- Command-line interface for all operations

## Requirements

- Python 3.8 or higher
- cryptography library

## Installation

Clone the repository:
