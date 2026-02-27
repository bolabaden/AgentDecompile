# Ghidra Basics: A Comprehensive Guide (Ghidra Rant 1)

This documentation provides an end-user targeted guide based on the "Ghidra Rant 1" tutorial. This guide covers essential workflows, from setting up repositories to solving advanced decompiler issues like stack param violations and custom storage.

---

## Table of Contents
- [Ghidra Basics: A Comprehensive Guide (Ghidra Rant 1)](#ghidra-basics-a-comprehensive-guide-ghidra-rant-1)
  - [Table of Contents](#table-of-contents)
  - [1. Project Management: Repositories](#1-project-management-repositories)
  - [2. The Code Browser Interface](#2-the-code-browser-interface)
  - [3. Symbol Tree \& Navigation](#3-symbol-tree--navigation)
  - [4. Data Type Manager](#4-data-type-manager)
  - [5. Listing View (Assembly)](#5-listing-view-assembly)
  - [6. Decompiler View (C-Code)](#6-decompiler-view-c-code)
  - [7. Advanced Concepts: Functions \& Calling Conventions](#7-advanced-concepts-functions--calling-conventions)
    - [Function Signatures](#function-signatures)
    - [Calling Conventions (19:09)](#calling-conventions-1909)
    - [Custom Storage (26:37)](#custom-storage-2637)
  - [8. Structures \& Vtables](#8-structures--vtables)
    - [Structures](#structures)
    - [Vtables (32:14)](#vtables-3214)
  - [9. Common Decompiler Issues \& Fixes](#9-common-decompiler-issues--fixes)
    - [extraout Variables (43:00)](#extraout-variables-4300)
    - [Stack Param Violations (47:36)](#stack-param-violations-4736)
    - [unaff Register Variables (49:48)](#unaff-register-variables-4948)
  - [Summary](#summary)

---

## 1. Project Management: Repositories
**Timestamp: 0:20**

Reverse engineering is often a collaborative effort. Ghidra handles this through "Shared Projects" using a Ghidra Server.

*   **Key Concept:** Use shared repositories to allow multiple users to check out files, make changes (like renaming functions), and check them back in.
*   **Visual:** The initial Ghidra window showing the "Active Project" with a folder icon representing either a local project or a server icon for a shared repo.

> **Transcript Snippet:** *"When you're starting out, don't just work in a vacuum. If you're in a team, set up a Ghidra Server. It lets you version control your reversing efforts so you don't step on each other's toes."*

---

## 2. The Code Browser Interface
**Timestamp: 1:08**

The **Code Browser** is the primary tool where reversing happens. It is launched by clicking the "Dragon" icon in the project window.

*   **Pro Tip:** You can customize the layout by dragging and dropping panes. Most users keep the Symbol Tree on the left, Listing in the middle, and Decompiler on the right.

---

## 3. Symbol Tree & Navigation
**Timestamp: 1:10**

The **Symbol Tree** is your map of the binary.

*   **Imports:** List of external DLLs/libraries the program calls.
*   **Functions:** Every identified subroutine in the program.
*   **Labels:** Global variables or specific addresses marked during analysis.
*   **Visual:** A tree-view pane on the left sidebar. Searching here is the fastest way to find entry points like `main` or specific API calls like `CreateFile`.

---

## 4. Data Type Manager
**Timestamp: 2:47**

Reversing is essentially the process of recovering data types.

*   **Workflow:** Import C headers (`File > Parse C Source`) to bring in standard Windows or Linux structures.
*   **Visual:** The bottom-left pane. It shows a library of "Built-in Types" and your project-specific "Archive."
*   **Usage:** Right-click a variable in the decompiler to "Retype" it using types found here.

---

## 5. Listing View (Assembly)
**Timestamp: 5:47**

The **Listing View** shows the raw assembly instructions and data bytes.

*   **Annotations:** Ghidra automatically adds "XREFs" (Cross-References) showing where a function or variable is used.
*   **Comments:** Use the `;` key to add a comment at any line.
*   **Visual:** The center pane with columns for Address, Bytes, Mnemonic (e.g., `MOV`, `PUSH`), and Operands.

---

## 6. Decompiler View (C-Code)
**Timestamp: 9:24**

The **Decompiler** translates assembly into readable C code.

*   **Renaming:** Click a variable (e.g., `uVar1`) and press `L` to give it a meaningful name.
*   **Synchronized Scrolling:** Clicking a line in the Decompiler will highlight the corresponding assembly in the Listing view.
*   **Visual:** The right-hand pane showing high-level logic like `if/else` loops and function calls.

---

## 7. Advanced Concepts: Functions & Calling Conventions
**Timestamp: 16:30**

### Function Signatures
Correcting function arguments is vital for clean code.
*   Right-click a function header and select **Edit Function**.
*   Manually set the return type and parameter names.

### Calling Conventions (19:09)
Ghidra needs to know how arguments are passed (Stack vs. Registers).
*   `__stdcall`: Common in Windows API; arguments are on the stack.
*   `__fastcall`: First few arguments are in registers (ECX, EDX).
*   `__cdecl`: Standard C convention where the caller cleans the stack.

### Custom Storage (26:37)
Sometimes compilers use "non-standard" conventions (e.g., passing an argument in `EBX`). 
*   **Fix:** In the **Edit Function** dialog, check **Use Custom Storage**. You can then manually assign specific registers to each parameter.

---

## 8. Structures & Vtables
**Timestamp: 30:26**

### Structures
When you see code like `*(int *)(param_1 + 0x14)`, it’s usually an object or a struct.
1.  Open the **Structure Editor**.
2.  Define fields (ints, pointers, strings) with their respective offsets.
3.  Retype `param_1` to your new struct name to see `param_1->field_name` in the decompiler.

### Vtables (32:14)
Used in C++ for virtual functions.
*   **Process:** Identify the global array of function pointers. Create a "Vtable Struct" where each member is a function pointer. Apply this struct to the object's first pointer.

---

## 9. Common Decompiler Issues & Fixes
**Timestamp: 42:50**

### extraout Variables (43:00)
Ghidra might show a variable as `extraout_EDX`. This happens when a function returns values in multiple registers.
*   **Fix:** Edit the function signature and ensure the return type and calling convention accurately reflect that multiple registers are modified.

### Stack Param Violations (47:36)
You may see a comment: `/* WARNING: Stack parameter of 4 bytes was actually 8 */`. 
*   **Reason:** The calling convention is wrong, or the number of arguments is incorrect.
*   **Fix:** Adjust the function signature until the warnings disappear.

### unaff Register Variables (49:48)
`unaff_EBX` indicates the decompiler thinks a register is being used before it was initialized.
*   **Common Cause:** This register is actually a "preserved" register that the function is supposed to save and restore. Ensure your function definition correctly identifies which registers are callee-saved.

---

## Summary
The "Ghidra Rant" emphasizes that **data typing is 90% of reversing**. By correctly defining your Repos, Symbols, and especially your Structures and Calling Conventions, you turn unreadable assembly into a high-level source representation that is easy to analyze.