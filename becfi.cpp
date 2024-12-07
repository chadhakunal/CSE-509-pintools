/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */
 
#include <stdio.h>
#include "pin.H"
#include <stack>
#include <map>

using std::stack;
using std::map;

FILE* trace;
stack<ADDRINT> call_stack;
map<ADDRINT, long> mismatches;

// This function is called before every instruction is executed
// and prints the IP
// VOID printip(VOID* ip) { fprintf(trace, "%p\n", ip); }

VOID onCall(ADDRINT call_site) {
    call_stack.push(call_site);
}

VOID onReturn(ADDRINT call_site, ADDRINT target) {
    // Compare with top three stack entries
    if (call_stack.empty()) return;
    stack<ADDRINT> temp;
    
    for (int i = 0; i < 4 && !call_stack.empty(); i++) {
        if (call_stack.top() == target) {
            call_stack.pop(); 
            return;
        } else {
            temp.push(call_stack.top());
            call_stack.pop();
        }
    }
    
    while (!temp.empty()) {
        call_stack.push(temp.top());
        temp.pop();
    }

    mismatches.find(call_site) == mismatches.end() ? mismatches[call_site] = 1 : mismatches[call_site]++;
}

// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID* v)
{
    if (INS_IsCall(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)onCall, IARG_BRANCH_TARGET_ADDR, IARG_END);
    } else if (INS_IsRet(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)onReturn, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_END);
    }
}
 
// This function is called when the application exits
VOID Fini(INT32 code, VOID* v)
{
    fprintf(trace, "--- Mismatch table ---\n");
    for (auto& pair: mismatches) {
        fprintf(trace, "Call site: %p, \tCount: %ld\n", (void*)pair.first, pair.second);
    }
}
 
/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
 
INT32 Usage()
{
    PIN_ERROR("This Pintool prints mismatches between calls and returns\n");
    return -1;
}
 
/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
 
int main(int argc, char* argv[])
{
    trace = fopen("mismatches.out", "w");
 
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();
 
    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);
 
    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
 
    // Start the program, never returns
    PIN_StartProgram();
 
    return 0;
}
