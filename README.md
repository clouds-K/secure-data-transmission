# Secure Data Transmission System

An educational end-to-end simulation of a secure data transmission chain, with an interactive Streamlit dashboard.
A message is compressed, encrypted, protected against errors, sent through a noisy channel, then recovered, with
every step visualized.


## How it works

**Sender**

1. **Huffman compression** reduces the message size.
2. **AES-256-CBC encryption** with a random IV; the key is derived from a password with SHA-256.
3. **CRC-32** integrity check computed over the IV and the ciphertext.
4. **Convolutional coding** (rate 1/2, constraint length K = 3, generators g1 = 5 and g2 = 7 in octal) adds redundancy.

**Channel**: a noisy channel flips bits with a configurable error probability.

**Receiver**: Viterbi decoding corrects the errors, the CRC-32 verifies the result, then the data is decrypted and
decompressed.

**Network**: an 8-node weighted graph (N0 to N7). The best route between two nodes is found with Dijkstra's
algorithm (NetworkX), and node failures can be simulated.

## Dashboard

The Streamlit app (`app.py`) has five tabs:

| Tab | Content |
|---|---|
| Network | Graph of the 8 nodes, shortest path, node failure simulation |
| Pipeline | Full run of the chain, step by step |
| Crypto & CRC | AES encryption/decryption and CRC-32 checks |
| Convolutional | Encoding and Viterbi decoding |
| BER | Bit error rate as a function of the channel error probability |

## Project structure

```
app.py                  Streamlit dashboard
modules/
  huffman.py            Huffman compression
  crypto_crc.py         AES-256-CBC and CRC-32
  convolutif.py         Convolutional encoder, noisy channel, Viterbi decoder
  reseau.py             Network graph and Dijkstra routing
  pipeline.py           End-to-end transmission pipeline
```

About 2,100 lines of Python.

## Getting started

```bash
python -m venv venv
venv\Scripts\activate          # Windows (PowerShell: venv\Scripts\Activate.ps1)
# source venv/bin/activate     # Linux / macOS
pip install -r requirements.txt
streamlit run app.py
```

## Security limitations

This project is for learning. In a real system you should change the following:

- The AES key is derived with a single SHA-256 of the password (no salt, no slow key-derivation function). Use
  PBKDF2, scrypt or Argon2.
- AES-CBC does not authenticate the data. Use an authenticated mode such as AES-GCM.
- CRC-32 detects accidental errors only. It does not protect against deliberate tampering.
- The demo password in `pipeline.py` is hard-coded for convenience.

## Author

**Khouloud Moumni**, cybersecurity engineering student at ISMAGI (Morocco), class of 2027.
[LinkedIn](https://www.linkedin.com/in/khouloud-moumni-346a4b2a6) · [GitHub](https://github.com/clouds-K)

## License

[MIT](LICENSE)
