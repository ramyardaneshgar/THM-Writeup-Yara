# THM-Writeup-Yara
Threat hunting using Yara, strings, and Loki to build 10+ custom rules and run 50+ scans for IOC, hex, and behavioral malware detection.

By Ramyar Daneshgar


## Task 2: What is YARA?

### Question 1: "What is the name of the base-16 numbering system that YARA can detect?"

I answered `hex`. YARA can search for string patterns and hexadecimal byte sequences in files. Hexadecimal (base-16) is often used in malware analysis to inspect and match raw binary content in a readable format.

### Question 2: "Would the text 'Enter your Name' be a string in an application?"

I answered `Yay`. This is a literal string—a human-readable sequence of characters—and YARA can match it when included in the `strings` section of a rule.

---

## Task 3: Deploy

I launched the virtual machine (VM) provided. This gave me access to the environment needed to test YARA locally.

---

## Task 4: Introduction to YARA Rules

I was asked to create and test a very basic YARA rule.

### Step 1: Create a test file

```bash
touch somefile
```

This created an empty file named `somefile`. I needed a target file to scan using a YARA rule.

### Step 2: Write a basic YARA rule

```bash
nano myfirstrule.yar
```

I used `nano` to create and edit a file called `myfirstrule.yar`. Inside, I wrote:

```yara
rule examplerule {
    condition:
        true
}
```

This rule always evaluates to true, meaning it should match any file, regardless of content. This was a sanity check to confirm YARA was functioning properly.

### Step 3: Run YARA on the file

```bash
yara myfirstrule.yar somefile
```

This command applied the rule to `somefile`. Since the rule’s condition is `true`, YARA printed `examplerule somefile`, indicating a match. This confirmed that YARA was correctly installed and functional.

---

## Task 5: Expanding on YARA Rules

In this section, I was shown how to define more detailed rules using string matching.

Here’s the syntax I reviewed:

```yara
rule sample {
    strings:
        $a = "malicious"
        $b = "payload"
    condition:
        $a or $b
}
```

This rule matches if either string "malicious" or "payload" is found in the target file. The `strings` section defines patterns, and the `condition` section defines logical rules using those patterns.

---

## Task 6: YARA Modules

I reviewed the use of **YARA modules**, which allow accessing metadata about files. For example:

- **PE module**: Useful for parsing Windows PE (Portable Executable) files, letting me access attributes like `pe.sections` or `pe.imphash`.
- **Cuckoo module**: Enables integration with Cuckoo sandbox results for dynamic behavior matching.
- **ELF module**: Targets Linux binaries.

These modules can be used in the `condition` block to detect specific file characteristics.

---

## Task 7: Other Tools and YARA

I explored tools that use YARA in real-world incident response:

### Loki

- A scanner that uses YARA rules and regex-based IOCs.
- Designed to be lightweight and used for live endpoint scanning.

### THOR

- A commercial tool similar to Loki, but with more advanced capabilities.
- Often used in enterprise environments for deeper scanning.

### FENRIR

- A bash-based IOC scanner for Unix systems.
- Focuses on quickly scanning files and processes using known indicators.

These tools wrap YARA functionality into higher-level detection pipelines.

---

## Task 8: Using LOKI and Its YARA Rule Set

### Step 1: Navigate to the suspicious file directory

```bash
cd /suspicious-files/file1
```

I moved to the directory where the target file was located.

### Step 2: Run LOKI to scan for IOCs

```bash
python3 ../../tools/Loki/loki.py -p .
```

The `-p` flag sets the path for scanning. LOKI scanned all files in the current directory (`.`), using its default set of YARA rules.

LOKI output included matches from built-in rules, showing which rules triggered on which files. I read the console output carefully to identify which rule matched and answered the corresponding TryHackMe question.

---

## Task 9: Writing a Custom Rule

### Step 1: Examine the file to find patterns

```bash
strings file1
```

I used `strings` to extract ASCII strings from the binary file. This is a basic static analysis technique for spotting readable content that might be unique or suspicious.

I noticed certain keywords or identifiers that appeared malware-like or uncommon.

### Step 2: Write a YARA rule to detect one of those strings

```yara
rule detect_file1 {
    strings:
        $x = "HardcodedAPIKey" // example string found
    condition:
        $x
}
```

I saved this rule as `file1_rule.yar`.

### Step 3: Test the rule

```bash
yara file1_rule.yar file1
```

If it returned `detect_file1 file1`, that meant the string match was successful, and the rule was working as expected.

---

## Task 10: YARA Logical Operators

I reviewed how to write conditions using AND, OR, and NOT to chain multiple string matches.

Example rule:

```yara
rule complex_match {
    strings:
        $a = "cmd.exe"
        $b = "powershell"
    condition:
        $a and $b
}
```

This rule only triggers if both strings are found in a file. I tested it against different files using `yara` as before.

---

## Task 11: Hexadecimal Strings

YARA also supports matching hex patterns:

```yara
rule hex_pattern {
    strings:
        $h = { E8 ?? ?? ?? ?? 83 C4 04 }
    condition:
        $h
}
```

The `??` wildcards allow matching unknown bytes. This was useful for finding shellcode or function calls with variable offsets.

I tested this rule against binaries by saving it as `hex.yar` and running:

```bash
yara hex.yar file1
```

---

## Task 12: Metadata in YARA Rules

Metadata adds context to a rule:

```yara
rule with_metadata {
    meta:
        author = "ramyar"
        description = "Detects suspicious API usage"
        date = "2025-04-10"
    strings:
        $a = "VirtualAlloc"
    condition:
        $a
}
```

This didn’t change rule logic but provided documentation useful during large-scale rule management and collaboration.

---

## Summary

Here are the **Lessons Learned** from completing the TryHackMe YARA room:

---

### **Lessons Learned**

1. **YARA is foundational for malware detection**  
   I learned how YARA rules function as pattern-matching logic that can detect malware by looking for strings, hexadecimal byte sequences, or file structure characteristics. These rules form the basis of many endpoint detection tools.

2. **Rule structure is modular and readable**  
   YARA rules consist of `meta`, `strings`, and `condition` sections, making them both powerful and human-readable. This modularity allows rapid rule creation, auditing, and sharing across incident response teams.

3. **Static analysis with `strings` is a key discovery step**  
   Before writing a rule, using `strings <file>` helped me extract plaintext values that could serve as indicators. This technique allowed me to create more precise, signature-based detections.

4. **Hexadecimal pattern matching is ideal for shellcode and obfuscation**  
   The ability to define byte patterns using `{}` and wildcards (`??`) is essential when detecting low-level malware behavior that doesn't contain readable strings. This is especially useful in packed or obfuscated binaries.

5. **YARA modules add advanced binary introspection**  
   Modules like `pe` allowed me to build rules based on PE header information, import tables, or section characteristics—crucial for detecting specific malware families or packing techniques.

6. **Tools like Loki operationalize YARA**  
   I gained practical experience using Loki, which wraps YARA into a usable IOC scanner for filesystems. It's lightweight and can be used in live environments for triaging suspicious hosts.

7. **Logical operators enhance rule precision**  
   By chaining strings with AND/OR/NOT, I could create rules that detected more specific combinations of indicators, reducing false positives in noisy datasets.

8. **Metadata aids attribution and rule lifecycle management**  
   Including author, description, and date in the `meta` section makes it easier to manage rules over time, especially when they are shared across SOC teams or imported into scanning engines.

9. **Testing and tuning rules is critical**  
   Writing a rule is only part of the process. Verifying its effectiveness using YARA CLI or tools like Loki ensures that it accurately identifies the intended threat while avoiding false matches.

10. **YARA knowledge scales across threat hunting, DFIR, and red teaming**  
   Whether I’m hunting for APT indicators, building behavioral detections, or testing my own payloads, YARA remains a flexible and powerful tool in any security workflow.

