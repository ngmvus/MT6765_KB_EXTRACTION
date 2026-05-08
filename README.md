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
 - # About Trustonic <t-base security platform # 
 	T-Base is a commercially deployed, security-critical Trusted Operating System (TOS) platform developed by Trustonic. It is engineered to operate within a Trusted Execution Environment (TEE), creating a hardened, secure partition on a system-on-chip (SoC) based on ARM TrustZone technology.

	Fundamentally, T-Base acts as the "Secure World" operating system. It provides an isolated computational environment that remains impervious to threats targeting the primary Rich Execution Environment (REE), such as Android or Linux. Even if the primary kernel is compromised (e.g., via root exploitation), the sensitive processes and cryptographic keys managed by T-Base remain protected due to the hardware-level isolation enforced by the processor.

	Key Components of the T-Base Platform
    + The T-Base architecture is modular and layered, comprising several distinct elements that ensure system-wide security:
   
	+ Kinibi Microkernel: The foundational core of the T-Base platform. It is a minimalist kernel responsible for essential system functions, including process scheduling, inter-process communication (IPC) management, and secure memory allocation. Its reduced codebase minimizes the attack surface.
	
	+ Trusted Applications (Trustlets): These are discrete, signed binary modules that execute within the TEE. Each Trustlet performs specific security tasks, such as managing biometric templates, handling mobile payment tokens, or processing Digital Rights Management (DRM) content. They operate in a sandbox, unable to interfere with one another.
	
	+ Secure Drivers: These software components interface directly with hardware peripherals while they are in a "secure state." Examples include drivers for secure input/output (like fingerprint sensors or secure touchscreens) and cryptoprocessors.

	+ Secure Monitor Call (SMC) Interface: This is the strictly regulated communication bridge between the Normal World (Android) and the Secure World (T-Base). All requests from the Android OS to the TEE must pass through this interface, which enforces authentication and input validation to prevent unauthorized commands.

 	+ Cryptographic Services: T-Base includes a suite of robust cryptographic primitives (e.g., AES, RSA, ECC) implemented in the secure domain. These allow for the generation, storage, and usage of private keys that never leave the TEE hardware, ensuring the integrity of device attestation.

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

	We predicted that the keybox ciphertext should be here. How to decrypt it into private keys? It is not easy. Despite the buggy SoC, the wrapping algorithm is not.

	Digging further, suspicious data has appeared:

       07 06 00 00 00 00 00 00 00 00 00 00 00 00 00 4D

	The data started from 0x1402C, and it matched exactly with:

       0706000000000000000000000000004d.tlbin

	Some Trusted binaries:
	<img width="597" height="790" alt="image" src="https://github.com/user-attachments/assets/0446dc96-d1cf-4ef5-8b0a-65433ce6bf32" />

	The hypothesis: At this point, we can guess why the trustlet UID was attached to the encrypted blob. Because the normal characteristic of an encrypted blob is extremely high entropy, the magic word **KEYMASTERATTESTDATA** and several bytes next to it is the header, the attached UUID is for usage privileges. As the UID is not matched, TEE won't allow it to read from RPMB. So the next move is to disassemble that suspicious Trustlet Binary(.tlbin).
  - # Exploration of Trustlet #
     We defined that 0706000000000000000000000000004d.tlbin is the target file for disassemble, right now, we will disassemble it.

	 A valuable resource we have is the MCLF loader, which map the memory for easier analysis: https://github.com/ghassani/mclf-ida-loader/blob/master/mclf_loader.py

	 This image contain the header of the targeted trustlet:
	 <img width="1440" height="143" alt="image" src="https://github.com/user-attachments/assets/42b0412d-d333-4e81-89ce-2359e1937310" />

        4D 43 4C 46 05 00 02 00 08 00 00 00 02 00 00 00 03 00 00 00 10 00 00 00 07 06 00 00 00 00 00 00 00 00 00 00 00 00 00 4D 00 00 00 00 01 00 00 00 00 10 00 00 3A E4 01 00 00 10 02 00 98 05 00 00 F8 AA 01 00 21 B7 01 00 00

     This header data is enough for memory map.

	 Extracted memory map from the header:
	 
        +---------------------------------------------------------------+
		| Offset | Bytes        | Data Definition   | Value             |
		+---------------------------------------------------------------+
		| 0x0	 | 4D 3C 4C 46  | Magic word		| "MCLF"			|
		| 0x04	 | 05 00 02 00  | Version(Min/Maj)	| v2.5				|
		| 0x08   | 08 00 00 00  | Flags				| 0x8				|
		| 0x0C	 | 02 00 00 00 	| memType			| 2					|
		| 0x10	 | 03 00 00 00	| serviceType		| 3(Driver/Service) |
		| 0x14	 | 10 00 00 00	| numInstances		| 16				|
		| 0x18	 | 07 06 .. 4D	| UUID				| (UUID bytes)		|
		| 0x28	 | 00 00 00 00 	| driverId			| 0					|
		| 0x2C	 | 01 00 00 00 	| numThreads		| 1					|
    	| 0x30	 | 00 10 00 00	| textVA			| 0x00001000		|
		| 0x34	 | 3A E4 01 00	| textLen			| 0x0001E43A		|
		| 0x38	 | 00 10 02 00	| dataVA			| 0x00021000		|
		| 0x3C	 | 98 05 00 00	| dataLen			| 0x00000598		|
		| 0x40	 | F8 AA 01 00	| bssLen			| 0x0001AAF8		|
		| 0x44	 | 21 B7 01 00	| entry				| 0x0001B721		|
		+---------------------------------------------------------------+

	 Now we can push it into Ghidra:

		+---------------------------------------------------------------------------------------------+
		| Segment | Start Address | Length  | File Offset | End Address | Type          | Permissions |
		+---------------------------------------------------------------------------------------------+
		| .text	  | 0x00001000	  | 0x1E43A | 0x0         | 0x1F43A     | Initialized   | R-X		  |
		| .data	  | 0x00021000	  | 0x598	| 0x1E43A     |	0x21598		| Initialized   | RW-	   	  |
		| .bss	  | 0x21598       |	0x1AAF8	| N/A         |	0x3C090     | Uninitialized	| RW-	 	  |
		+---------------------------------------------------------------------------------------------+

	Gorgeous!!!

	<img width="1917" height="926" alt="image" src="https://github.com/user-attachments/assets/3b5071a6-2c7b-4528-8e65-85e1d29b1083" />
	<img width="1915" height="983" alt="image" src="https://github.com/user-attachments/assets/54557af4-3e1c-4c53-ade2-4fab5d92bd62" />
	<img width="1904" height="982" alt="image" src="https://github.com/user-attachments/assets/4893bf55-9850-4d7a-8349-62339a9f836c" />

	It is evident that the trustlet binary wasn't treated well before going to production, leaving it unstripped. From the string view, we can assume that this trustlet definitely carries the provision process(factory) and parses the attestation data.

	At this stage, the analysis process becomes harsher as it requires various logic tracing and disassembling the boot stages more deeply. Because of unstripped images, the logic tracing process will be easier.

	Based on the string view, the trustlet can be identified as teeKeyMaster4

	Next stage, we will analyze the whole TEE to unveil the decryption processes.

  - # TEE analysis #
     Some discrete data we have: TEEdmesg.txt(Acquired at early boot stage after LK)

	A quotation from the log file:
	
	 	[    4.669389] (0)[532:mcDriverDaemon]Trustonic TEE: admin_open: daemon connection open, TGID 532
		[    4.679228] (3)[282:rpmb_open]Trustonic TEE: ERROR -1 mcp_cmd: open session: res 32
		[    4.679234] (2)[229:tee_log]Trustonic TEE: 201(1)|Mounting partition 1...
		[    4.679241] (2)[229:tee_log]Trustonic TEE: 201(1)|[STH2] ERROR static_fileServerMountFileSystem : failed to mount partition 1
		[    4.680846] (1)[229:tee_log]Trustonic TEE: 401(2)|TA SPT2 : Starting.
		[    4.680867] (1)[229:tee_log]Trustonic TEE: 401(2)|TA SPT2 : tbase info.
		[    4.680873] (1)[229:tee_log]Trustonic TEE: 401(2)|tlApi version    =  0x00010014
		[    4.680879] (1)[229:tee_log]Trustonic TEE: 401(2)|productId        = t-base-MTK-A64-Android-410a-V107-20190917_223909_73476_99814
		[    4.680885] (1)[229:tee_log]Trustonic TEE: 401(2)|versionMci       = 0x00010007
		[    4.680891] (1)[229:tee_log]Trustonic TEE: 401(2)|versionSo        = 0x00020002
		[    4.680896] (1)[229:tee_log]Trustonic TEE: 401(2)|versionMclf      = 0x00020005
		[    4.680902] (1)[229:tee_log]Trustonic TEE: 401(2)|versionContainer = 0x00020001
		[    4.680908] (1)[229:tee_log]Trustonic TEE: 401(2)|versionMcConfig  = 0x00000003
		[    4.680913] (1)[229:tee_log]Trustonic TEE: 401(2)|versionTlApi     = 0x00010014
		[    4.680919] (1)[229:tee_log]Trustonic TEE: 401(2)|versionDrApi     = 0x00010004
		[    4.680925] (1)[229:tee_log]Trustonic TEE: 401(2)|versionCmp       = 0x00000000
		[    4.686841] (5)[532:mcDriverDaemon]Trustonic TEE: ERROR -1 mcp_cmd: open session: res 8
		[    4.692187] (2)[229:tee_log]Trustonic TEE: 201(0)|Mounting partition 1...
		[    4.694477] (2)[229:tee_log]Trustonic TEE: 201(1)|Partition 1 successfully mounted
		[    4.701387] (1)[229:tee_log]Trustonic TEE: 601(1)|[SEC DRV] T[DEVAPC] (Infra)reg0-0 = 0x10100000
		...
		[    4.705095] (1)[229:tee_log]Trustonic TEE: 601(1)|[SEC DRV] T[DEVAPC] <6><7><6><5>
		[    4.706799] (3)[229:tee_log]Trustonic TEE: 701(1)|[<t Driver Drspi] 1.0, Build Feb 22 2024, 01:00:22
		[    4.741325] (2)[229:tee_log]Trustonic TEE: a01(3)|teeKeyMaster4-package-4.0.2-20190104_130719_3818_90370
		[    4.741338] (2)[229:tee_log]Trustonic TEE: a01(3)|tlTeeKeymaster: Keymaster TA version 0400.0000
		[    4.741344] (2)[229:tee_log]Trustonic TEE: a01(3)|tlTeeKeymaster: Limiting API version to 4
		[    4.741350] (2)[229:tee_log]Trustonic TEE: a01(3)|tlTeeKeymaster: Neon instructions will be used
		[    4.744525] (2)[229:tee_log]Trustonic TEE: b01(3)|t-base-MTK-ARMv8-Android-400C-V001-20180713_214233_52230_81596
		[    4.744546] (2)[229:tee_log]Trustonic TEE: b01(3)|[DrAndroid] Version 1.0
		[    4.745043] (2)[229:tee_log]Trustonic TEE: a01(3)|[verifiedBoot_GetBootPatchlevel] verifiedBoot_GetBootPatchlevel boot_patchlevel = 135c145
		[    8.352682] (3)[229:tee_log]Trustonic TEE: c01(4)|t-base-MTK-ARMv8-Android-400C-V001-20180713_214233_52230_81596
		[    8.352708] (3)[229:tee_log]Trustonic TEE: c01(4)|tlTeeGatekeeper: GateKeeper TA version 0100.258
		[    9.735872] (1)[229:tee_log]Trustonic TEE: 104(4)|MSH ASLR c01, UUID=09080000-0000-0000-0000-000000000000, code offset 0x00000000, mclib offset 0x07f62000
		[    9.759932] (0)[229:tee_log]Trustonic TEE: c01(4)|[crypto_eng] tlMain(): main... May 20 202110:28:30
		[    9.931593] (5)[229:tee_log]Trustonic TEE: c01(5)|Wait for notification.
		[    9.931608] (5)[229:tee_log]Trustonic TEE: c01(5)|[<t Trusted Application Fingerprint Cards], Build Aug 20 2020, 11:21:39
		[    9.931614] (5)[229:tee_log]Trustonic TEE: c01(5)|tlApi version 0x00010014
		[    9.931618] (5)[229:tee_log]Trustonic TEE: c01(5)|productId        = t-base-MTK-A64-Android-410a-V107-20190917_223909_73476_99814
		[    9.931623] (5)[229:tee_log]Trustonic TEE: c01(5)|versionMci       = 0x00010007
		[    9.931628] (5)[229:tee_log]Trustonic TEE: c01(5)|versionSo        = 0x00020002
		[    9.931632] (5)[229:tee_log]Trustonic TEE: c01(5)|versionMclf      = 0x00020005
		[    9.931637] (5)[229:tee_log]Trustonic TEE: c01(5)|versionContainer = 0x00020001
		[    9.931641] (5)[229:tee_log]Trustonic TEE: c01(5)|versionMcConfig  = 0x00000003
		[    9.931645] (5)[229:tee_log]Trustonic TEE: c01(5)|versionTlApi     = 0x00010014
		[    9.931650] (5)[229:tee_log]Trustonic TEE: c01(5)|versionDrApi     = 0x00010004
		[    9.931654] (5)[229:tee_log]Trustonic TEE: c01(5)|versionCmp       = 0x00000000
	
	The log provides a clear view of the initialization stages of TEE.

	(1) 4.669389 -> 4.694477: TEEOS preparation, mounting files from mcRegistry(tlbins and drbins are being loaded after that).
	(2) 4.701387 -> 4.705095: DEVAPC doin its job(05120000000000000000000000000000.drbin/tlbin)
	(3) 4.701387 -> 4.706799: Drspi driver loaded(030b0000000000000000000000000000.drbin/tlbin)
	(4)	4.741325 -> 4.741350: tlTeeKeymaster4 loaded(0706000000000000000000000000004d.tlbin)
	(5)	4.744525 -> 4.745043: DrAndroid loaded(07170000000000000000000000000000.drbin/tlbin)
	(6) 8.352682 -> 9.759932: TlTeeGateKeeper loaded, active and calling crypto engine(07061000000000000000000000000000.tlbin)
	(7) 9.931608 -> 9.931654: Fingerprint manager loaded()
	
# Project progress #
 - 45% (analyzing crypto accelerator registers/mapping syscalls).
