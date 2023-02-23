# Phobos Ransomware CUDA Brute

**Because sometimes the ~~truth~~ CPU isn't good enough.**

## What is this

This is a proof of script to brute-force the encryption key used in Phobos ransomware. **Please keep in mind this has never been successfully used in real life scenario so far.** More information is available in the [article](https://cert.pl/en/posts/2023/02/breaking-phobos/) that describes our thought process behind it.

## Building

You'll need a CUDA-compatible GPU as well as the CUDA compilation tools. Turing architecture worked best for us but it's possible that using a newer/older one could have some benefits or work better for you.

```shell
nvcc bruteforce_range.cpp main.cu sha256.cu -O3 -rdc=true --gpu-architecture=compute_75 --gpu-code=sm_75 -o brute.exe
```

## Running

To run the script you'll need to gather a bunch of information about the ransomware process from the infected host, as well as a pair of encrypted and unencrypted file.

To get the estimate on total keyspace run:

```shell
# ./brute.exe keyspace <config file>
./brute.exe keyspace sample_data/config.json
```

This will give you the total number of needed of iterations you'll need to perform in the next step.


To run the cracking process:
```shell
# ./brute.exe crack <config file> <cleartext file> <encrypted file> <start_step> <end_step>
./brute.exe crack config.json tofu.jpg tofu.enc 1 603
```

```cmd
C:\Users\phobos\cuda-brute>brute.exe crack sample_data\config.json sample_data\tofu.jpg sample_data\tofu.enc 1 603

State: 0 (3.05916e+18%)
Starting the SHA task
Starting the AES task
Waiting for tasks
Doing the CPU task
CPU task done!
Batch has taken: 1.001s

State: 512 (84.743%)
Starting the SHA task
Starting the AES task
Waiting for tasks
Doing the CPU task
No more things to try!
CPU task done!
Batch has taken: 2.87958s

State: 603 (99.8342%)
Starting the SHA task
Starting the AES task
Waiting for tasks
Doing the CPU task
No more things to try!
CPU task done!
Batch has taken: 2.81375s

State: 604 (100%)
Starting the SHA task
Starting the AES task
Waiting for tasks
Doing the CPU task
Found... something?
ac9f6d86f7cc156a40601972c4257c548a1c885b4bc3f461c988cae68505eb55
```

If you really want to make a serious attempt at using this, be sure to set the `CUDA_VISIBLE_DEVICES` envvar, and fine-tine the `STREAM_NO` and `BATCH_SIZE` consts.

## Credits

* AES256: Byte-oriented AES-256 implementation. - [Ilya O. Levin, Hal Finney](http://www.literatecode.com)
* SHA256: [SHA256CUDA](https://github.com/moffa13/SHA256CUDA) - [moffa13](https://github.com/moffa13)
* Rest: [CERT Polska](https://cert.pl/) - [Jarosław Jedynak](https://tailcall.net/) / [Michał Praszmo](https://naz.p4.team/)

## Tests

The script was tested and **should** compile/work on:

* `Cuda compilation tools, release 10.1, V10.1.243`
* `Cuda compilation tools, release 11.1, V11.1.105`
* `GeForce RTX 2080` - `Driver Version: 450.66       CUDA Version: 11.0`
* `GeForce GTX 1050` - `Driver Version: 526.47       CUDA Version: 12.0`
