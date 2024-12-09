#define MAX_STACK_CHECK_DEPTH 4

#include <iostream>
#include <fstream>
#include <stack>
#include <unordered_map>
#include "pin.H"

using std::cerr;
using std::endl;
using std::ios;
using std::ofstream;
using std::string;
using std::unordered_map;
using std::pair;
using std::make_pair;
using std::stack;
using std::vector;

TLS_KEY tls_key;

struct AddressInfo {
    std::string image_name;
    std::string section_name;
    ADDRINT offset;
    std::string routine_name;
};

struct ThreadData {
    stack<pair<ADDRINT, ADDRINT>> call_stack;
    unordered_map<ADDRINT, pair<ADDRINT, UINT64>> mismatches;
};

std::unordered_map<ADDRINT, AddressInfo> address_map;

ofstream OutFile;

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "outputs/backward_edge_cfi.out", "specify output file name"); 

ThreadData* GetThreadData(THREADID threadid) {
    return static_cast<ThreadData*>(PIN_GetThreadData(tls_key, threadid));
}

// Handle thread start
VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v) {
    ThreadData* tdata = new ThreadData();  // Allocate thread-specific data
    PIN_SetThreadData(tls_key, tdata, threadid);
    std::cout << "Thread " << threadid << " started." << std::endl;
}

VOID ThreadFini(THREADID threadid, const CONTEXT* ctxt, INT32 code, VOID* v) {
    ThreadData* tdata = GetThreadData(threadid);
    OutFile.setf(ios::showbase);
    OutFile << "Thread " << threadid << " mismatches:" << std::endl;
    OutFile << std::left << std::setw(18) << "Address" 
        << std::setw(8) << "Count" 
        << std::setw(30) << "Calling routine"
        << std::setw(30) << "Expected return routine"
        << std::setw(30) << "Routine" 
        << std::setw(15) << "Section" 
        << std::setw(10) << "Offset" 
        << std::setw(35) << "Image"
        << std::endl;
    OutFile << std::string(95, '-') << std::endl;

    for (const auto& pair : tdata->mismatches) {
        const AddressInfo& info = address_map[pair.first];
        const AddressInfo& info2 = address_map[pair.second.first];
        OutFile << std::left << std::setw(18) << std::hex << pair.first 
                << std::setw(8) << std::dec << pair.second.second 
                << std::setw(30) << info.routine_name 
                << std::setw(30) << info2.routine_name
                << std::setw(15) << info.section_name 
                << std::setw(10) << std::hex << info.offset 
                << std::setw(35) << info.image_name 
                << std::endl;
    }
    OutFile << std::endl;

    delete tdata;
    std::cout << "Thread " << threadid << " finished." << std::endl;
}

// Analysis routine for calls
VOID HandleCall(THREADID threadid, ADDRINT call_address, ADDRINT return_address) {
    ThreadData* tdata = GetThreadData(threadid);
    tdata->call_stack.push(make_pair(call_address, return_address));
}

// Analysis routine for returns
VOID HandleReturn(THREADID threadid, ADDRINT call_address, ADDRINT target_address, ADDRINT rsp) {
    ThreadData* tdata = GetThreadData(threadid);
    ADDRINT return_address;

    if (PIN_SafeCopy(&return_address, (VOID *)target_address, sizeof(ADDRINT)) == sizeof(ADDRINT)) {
        if (!tdata->call_stack.empty()) {
            stack<pair<ADDRINT, ADDRINT> > temp_stack;
            bool match_found = false;

            for (int i = 0; i < MAX_STACK_CHECK_DEPTH && !tdata->call_stack.empty(); i++) {
                pair<ADDRINT, ADDRINT> stack_top = tdata->call_stack.top();
                if (stack_top.second == return_address) {
                    match_found = true;
                    tdata->call_stack.pop();
                    break;
                } else {
                    std::cout<<"Mismatch! Checking next stack entry" << std::endl;
                    temp_stack.push(stack_top);
                }
                tdata->call_stack.pop();
            }

            if (!match_found) {
                while(!temp_stack.empty()) {
                    tdata->call_stack.push(temp_stack.top());
                    temp_stack.pop();
                }

                // Log the mismatch
                if (tdata->mismatches.find(call_address) == tdata->mismatches.end()) {
                    tdata->mismatches[call_address] = { tdata->call_stack.top().first, 1 };
                } else {
                    tdata->mismatches[call_address].second++;
                }
                
                std::cout << "Mismatch detected! Call address: 0x" << std::hex << call_address
                        << ", Expected return address: 0x" << tdata->call_stack.top().second
                        << ", Actual return address: 0x" << return_address 
                        << std::endl;
            }
        } else {
            std::cout << "Warning: Return without corresponding call!" << std::endl;
        }
    } else {
        std::cout << "Failed to read return address from stack!" << std::endl;
    }
}

SEC FindSectionContainingAddress(IMG img, ADDRINT address) {
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
        if (address >= SEC_Address(sec) && address < SEC_Address(sec) + SEC_Size(sec)) {
            return sec;  // Found the section
        }
    }
    return SEC_Invalid();  // No section contains the address
}

VOID RecordAddressInfo(ADDRINT address) {
    PIN_LockClient();

    IMG img = IMG_FindByAddress(address);
    if (!IMG_Valid(img)) {
        std::cout << "Address 0x" << std::hex << address << " not in any valid image." << std::endl;
        PIN_UnlockClient();
        return;
    }

    std::string image_name = IMG_Name(img);

    SEC sec = FindSectionContainingAddress(img, address);
    std::string section_name = SEC_Valid(sec) ? SEC_Name(sec) : "<unknown>";

    ADDRINT offset = address - IMG_LowAddress(img);

    std::string routine_name = "<unknown>";
    RTN rtn = RTN_FindByAddress(address);
    if (RTN_Valid(rtn)) {
        routine_name = RTN_Name(rtn);
    }

    address_map[address] = {image_name, section_name, offset, routine_name};
    PIN_UnlockClient();
}

VOID Routine(RTN rtn, VOID* v) {
    if (RTN_Valid(rtn)) {
        PIN_LockClient();
        ADDRINT rtn_address = RTN_Address(rtn);
        std::string rtn_name = RTN_Name(rtn);
        if (address_map.find(rtn_address) != address_map.end()) {
            address_map[rtn_address].routine_name = rtn_name;
        }
        PIN_UnlockClient();
    } else {
        std::cout<<"Invalid routine!" << std::endl;
    }
}

VOID Instruction(INS ins, VOID *v) {
    // Instrument CALL instructions
    if (INS_IsCall(ins))
    {
        ADDRINT call_address = INS_Address(ins);
        ADDRINT return_address = INS_NextAddress(ins);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)HandleCall, IARG_THREAD_ID, IARG_ADDRINT, call_address, IARG_ADDRINT, return_address, IARG_END);
    }

    // Instrument RET instructions
    else if (INS_IsRet(ins))
    {
        ADDRINT call_address = INS_Address(ins);
        ADDRINT target_address = IARG_BRANCH_TARGET_ADDR;
        RecordAddressInfo(target_address);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)HandleReturn, IARG_THREAD_ID, IARG_ADDRINT, call_address, IARG_ADDRINT, target_address);
    }
}

VOID Fini(INT32 code, VOID* v) {
    OutFile.close();
}

INT32 Usage() {
    cerr << "This tool implements Backward Edge CFI" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

BOOL FollowChild(CHILD_PROCESS cProcess, VOID* userData)
{
    return TRUE; // run childProcess under Pin instrumentation
}

int main(int argc, char *argv[]) {
    PIN_InitSymbols();

    if (PIN_Init(argc, argv)) return Usage();
    PIN_AddFollowChildProcessFunction(FollowChild, 0);

    tls_key = PIN_CreateThreadDataKey(nullptr); 

    OutFile.open(KnobOutputFile.Value().c_str());

    INS_AddInstrumentFunction(Instruction, 0);
    RTN_AddInstrumentFunction(Routine, 0);
    PIN_AddThreadStartFunction(ThreadStart, nullptr);
    PIN_AddThreadFiniFunction(ThreadFini, nullptr);
    PIN_AddFiniFunction(Fini, 0);
 
    PIN_StartProgram();

    return 0;
}
