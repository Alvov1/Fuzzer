# Fuzzer
Windows mutation-based format fuzzer implementation. Performs the following actions:
- Changing the original configuration file (single-byte replacement, replacement of several bytes, appending to a file);
- Replacing bytes with boundary values (0x00, 0xFF, 0xFFFF, 0xFFFFFF, 0xFFFFFFFF, 0xFFFF/2, 0xFFFF/2+1, 0xFFFF/2-1, etc.);
- Finding characters in the file that separate fields (“,:=;”);
- Expansion of field values in the file (append to the end, increase the length of lines in the file);
- Finding field boundaries in a file based on the analysis of several configuration files;
- Detection of errors that have occurred in the application during its execution;
- Obtaining the error code and status of the stack, registers and other information at the time of the error;

Supports automatic mode of operation, in which the sequential replacement of bytes in the file is performed;
