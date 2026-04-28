# Introduction #

This research aims to achieve successful keybox extraction, and the analysis is based on a static method.

# Preparation #

The materials:
- Oppo A15 (identified as CPH2185, based on MT6765 SoC) (dismantled state)
- mtkclient (https://github.com/bkerler/mtkclient)
- Gemini AI (for logic analyzing)
- Ghidra (for disassembly)
- A human brain (research dispatcher and auditor)

# Research Initialization #

- About the Oppo A15, it is known that the device is based on MT6765(aka Helio P35), which is such a favourable environment for me to start an analysis on it.
- Known information:
	+ TEE is supplied and customized by Mediatek, based on Trustonic Kinibi 410A.
    + The labeled partitions known as tee1 and tee2 are extractable through mtkclient, and they contain a FULL image of TEEOS..
	+ MCLF headers of TEE executables are identical and widely known.
	+ The dumped TEEOS image is packed with 3 instructions: AArch64, Arm32, Thumb-2 (Little endian).
	+ Leaked Kinibi SDK from qcom-leaked-source, which contains the 2013 Trustonic Kinibi SDK.
- Known platform bugs and exploits:
	+ Kamakiri2 (working greatly).
	+ TOCTOU (LK patching-on-the-fly).
	+ Unstripped TEEOS image (contains plenty of readable strings).
	+ Identical function pointer table

# The Action #



# Project progress #
 - 30% (unveiling the TEE unwrap logic)
