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
	+ TEE TrustedOS is supplied to Oppo and customized by Mediatek, based on Trustonic Kinibi 410A.
    + The labeled partitions known as tee1 and tee2 are extractable through mtkclient, and they contain a FULL image of TEEOS.
	+ MCLF headers of TEE executables are identical and widely known.
	+ The dumped TEEOS image is packed with 3 instructions: AArch64, Arm32, Thumb-2 (Little endian).
	+ Leaked Kinibi SDK from qcom-leaked-source, which contains the 2013 Trustonic Kinibi SDK.
- Known platform bugs and exploits:
	+ Kamakiri2 (working greatly).
	+ TOCTOU (LK patching-on-the-fly).
	+ Unstripped TEEOS image (contains plenty of readable strings).
	+ Identical function pointer table

# Definitions #
 - # Keybox? What is it? #
	The Keybox is a part of Android's Root of Trust, which proves the overall integrity of your device. This schematic illustrates the keybox usage activity:

           NORMAL WORLD (REE)                SECURE MONITOR (EL3)               SECURE WORLD (TEE)
        +-----------------------+          +-----------------------+          +-----------------------+
        |   Application Layer   |          |                       |          |  Trusted Application  |
        |    (Keystore API)     |          |   State Preservation  |          |   (Keymaster/Signer)  |
        +-----------+-----------+          |  (Exception Handling) |          +-----------+-----------+
                    |                      |                       |                      ^
          (1) Request Attestation          +-----------+-----------+              (4) Dispatch Command
                    |                                  |                                  |
                    v                                  v                                  v
        +-----------------------+          +-----------------------+          +-----------------------+
        |      Keystore HAL     |   (2)    |    Security Gateway   |   (3)    |     TEE Kernel/OS     |
        |   (Command Packing)   |--------->|      (SMC Entry)      |--------->|  (System Call Layer)  |
   	    +-----------------------+   SMC    +-----------------------+          +-----------+-----------+
     	                                                                                  |
     		                                                                       (5) Fetch & Unwrap
    	                                                                                  |
    	+---------------------------------------------------------------------------------v-------------------+
    	|                                     HARDWARE LAYER                                                  |
    	|   +-----------------------+          +-----------------------+          +-----------------------+   |
    	|   |    Secure Storage     |          |  Cryptographic Accel  |          |  Root of Trust (RoT)  |   |
    	|   |   (RPMB/Flash Part)   |          |     (RSA/AES/ECC)     |          |      (Efuse/HUK)      |   |
    	|   +-----------------------+          +-----------------------+          +-----------------------+   |
    	+-----------------------------------------------------------------------------------------------------+

	Trustonic Kinibi TEE follows the same model. Therefore, we can pinpoint the Keybox ciphertext location.
 - # RPMB? Again? #
 	RPMB(aka Replay Protected Memory Block) is a specific memory region protected with hardware-based methods, usually for storing sensitive, immutable information. The ability of this region is that it is tamper-proof. The authentication is protected with a hard-coded Authentication Key provisioned from the fabrication stage of the mobile device. It stores the write counter, critical information, and can only be read by the secure elements of the device.
	An RPMB contains these sections(according to Wikipedia):

		+---------------------------------------------------------------+
		| Section            | Size                                     |
		+---------------------------------------------------------------+
		| Authentication Key | 32 bytes Write-only                      |
		| Write Counter      | 4 bytes (32 bits) Read-only              |
		| Data               | 128Kb to 16Mb Read-Write                 |
		+---------------------------------------------------------------+
 - #  #
# The action #
 - # Locating the attestation data ciphertext #
	As we mentioned, the target ciphertext may be stored in a secure place like RPMB.
	
	The collected raw RPMB dump from my device:
	<img width="613" height="43" alt="image" src="https://github.com/user-attachments/assets/b324ec9c-fa24-40ad-9d3b-ed5320b0da90" />

	The hexadecimal data in RPMB:
	<img width="1919" height="787" alt="image" src="https://github.com/user-attachments/assets/6c34c072-ac70-4299-8df2-c3bbc90155eb" />

	As we have seen, the data begins at 0x8000 with high entropy data behind it. As we don't know what it is, we should skim it further.

	Gotcha!
	<img width="1919" height="184" alt="image" src="https://github.com/user-attachments/assets/3ecac2e6-a268-4491-a54a-2febebc0ec72" />

	We predicted that the keybox ciphertext should be here. How to decrypt it into private keys? It is not easy. Despite of buggy SoC, the wrapping algorithm is not.

	Digging further, a suspicious data has appeared:

       07 06 00 00 00 00 00 00 00 00 00 00 00 00 00 4D

	The data started from 0x1402C, and it matched exactly with:

       0706000000000000000000000000004d.tlbin

	Some Trusted binaries:
	<img width="597" height="790" alt="image" src="https://github.com/user-attachments/assets/0446dc96-d1cf-4ef5-8b0a-65433ce6bf32" />

	The hypothesis: At this point, we can guess why the trustlet UID was attached to the encrypted blob. Because the normal characteristic of an encrypted blob is extremely high entropy, the magic word **KEYMASTERATTESTDATA** and several bytes next to it is the header, the attached UUID is for usage privileges. As the UID is not matched, TEE won't allow it to read from RPMB. So the next move is to disassemble that suspicious Trustlet Binary(.tlbin).

# Project progress #
 - 30% (unveiling the TEE unwrap logic)
