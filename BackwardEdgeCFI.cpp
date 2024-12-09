#define MAX_STACK_CHECK_DEPTH 4

#include <iostream>
#include <fstream>
#include <functional>
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
using std::hash;

TLS_KEY tls_key;

struct AddressInfo {
    std::string image_name;
    std::string section_name;
    ADDRINT offset;
    std::string routine_name;
};

struct hash_pair {
    template <class T1, class T2>
    size_t operator()(const pair<T1, T2>& p) const
    {
        size_t hash1 = hash<T1> {}(p.first);
        size_t hash2 = hash<T2> {}(p.second);
        return hash1 ^ (hash2 + 0x9e3779b9 + (hash1 << 6) + (hash1 >> 2));
    }
};

struct ThreadData {
    stack<pair<ADDRINT, ADDRINT> > call_stack;
    unordered_map<pair<ADDRINT, ADDRINT>, UINT64, hash_pair> mismatches;
};

// Map of address to routine names, image names, offset
std::unordered_map<ADDRINT, AddressInfo> address_map;

// Output file that contains summary of mismatches
ofstream OutFile;
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "outputs/backward_edge_cfi.out", "specify output file name"); 

ThreadData* GetThreadData(THREADID threadid) {
    return static_cast<ThreadData*>(PIN_GetThreadData(tls_key, threadid));
}

// Handle thread start
VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v) {
    ThreadData* tdata = new ThreadData();  // Allocate thread-specific data
    PIN_SetThreadData(tls_key, tdata, threadid);
}

// Handle thread finish and write summary of the thread to Outfile
VOID ThreadFini(THREADID threadid, const CONTEXT* ctxt, INT32 code, VOID* v) {
    ThreadData* tdata = GetThreadData(threadid);
    OutFile.setf(ios::showbase);
    OutFile << "Thread " << threadid << " mismatches:" << std::endl;
    OutFile << std::left << std::setw(18) << "Instruction" 
        << std::setw(18) << "Address" 
        << std::setw(8) << "Count" 
        << std::setw(30) << "Routine" 
        << std::setw(15) << "Section" 
        << std::setw(10) << "Offset" 
        << std::setw(35) << "Image"
        << std::endl;
    OutFile << std::string(95, '-') << std::endl;

    if(tdata->mismatches.size() > 0) {
        for (const auto& pair : tdata->mismatches) {
            const AddressInfo& call_info = address_map[pair.first.first];
            OutFile << std::left << std::setw(18) << "Call" 
                    << std::setw(18) << std::hex << pair.first.first 
                    << std::setw(8) << std::dec << pair.second 
                    << std::setw(30) << call_info.routine_name 
                    << std::setw(15) << call_info.section_name 
                    << std::setw(10) << std::hex << call_info.offset 
                    << std::setw(35) << call_info.image_name 
                    << std::endl;
            
            const AddressInfo& ret_info = address_map[pair.first.second];
            OutFile << std::left << std::setw(18) << "Return" 
                    << std::setw(18) << std::hex << pair.first.second
                    << std::setw(8) << std::dec << pair.second 
                    << std::setw(30) << ret_info.routine_name 
                    << std::setw(15) << ret_info.section_name 
                    << std::setw(10) << std::hex << ret_info.offset 
                    << std::setw(35) << ret_info.image_name 
                    << std::endl;
            OutFile << std::endl;
        }
        OutFile << std::endl;
    } else {
        OutFile << "No Mismatches!" << std::endl;
    }

    delete tdata;
}

// Analysis routine for calls
// call_address: address of the call instruction
// expected_return_address: return address a ret should jump back to
VOID HandleCall(THREADID threadid, ADDRINT call_address, ADDRINT expected_return_address) {
    ThreadData* tdata = GetThreadData(threadid);
    tdata->call_stack.push(make_pair(call_address, expected_return_address));
}

// Analysis routine for returns
// return_address: target ret will jump to
// current_address: address of the ret instruction
VOID HandleReturn(THREADID threadid, ADDRINT return_address, ADDRINT current_address) {
    ThreadData* tdata = GetThreadData(threadid);

    if (tdata->call_stack.empty()) {
        std::cout << "Warning: Return without corresponding call!" << std::endl;
        return;
    }

    stack<pair<ADDRINT, ADDRINT> > temp_stack;
    bool match_found = false;

    for (int i = 0; i < MAX_STACK_CHECK_DEPTH && !tdata->call_stack.empty(); i++) {
        pair<ADDRINT, ADDRINT> stack_top = tdata->call_stack.top();
        tdata->call_stack.pop();
        if (stack_top.second == return_address) {
            match_found = true;
            break;
        } else {
            temp_stack.push(stack_top);
        }
    }

    if (!match_found) {
        while(!temp_stack.empty()) {
            tdata->call_stack.push(temp_stack.top());
            temp_stack.pop();
        }

        // Log the mismatch
        pair<ADDRINT, ADDRINT> stack_top = tdata->call_stack.top();

        pair<ADDRINT, ADDRINT> mismatches_key = {stack_top.first, current_address};
        tdata->mismatches[mismatches_key]++;
        std::cout << "Mismatch detected at address: 0x" << std::hex << current_address
                << ", Called from address: 0x" << stack_top.first
                << ", Expected return target: 0x" << stack_top.second
                << ", Actual return target: 0x" << return_address  
                << ", Routine: " << address_map[current_address].routine_name 
                << ", Image: " << address_map[current_address].image_name 
                << ", Section: " << address_map[current_address].section_name 
                << ", Offset: 0x" << address_map[current_address].offset
                << std::endl;
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
        RecordAddressInfo(call_address);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)HandleCall, IARG_THREAD_ID, IARG_ADDRINT, call_address, IARG_ADDRINT, return_address, IARG_END);
    }

    // Instrument RET instructions
    else if (INS_IsRet(ins))
    {
        ADDRINT ret_address = INS_Address(ins);
        RecordAddressInfo(ret_address);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)HandleReturn, IARG_THREAD_ID, IARG_BRANCH_TARGET_ADDR, IARG_ADDRINT, ret_address, IARG_END);
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
