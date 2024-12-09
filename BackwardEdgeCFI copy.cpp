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
    stack<pair<ADDRINT, ADDRINT> > call_stack;
    unordered_map<ADDRINT, UINT64> mismatches;
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
        << std::setw(30) << "Routine" 
        << std::setw(15) << "Section" 
        << std::setw(10) << "Offset" 
        << std::setw(35) << "Image"
        << std::endl;
    OutFile << std::string(95, '-') << std::endl;

    for (const auto& pair : tdata->mismatches) {
        const AddressInfo& info = address_map[pair.first];
        OutFile << std::left << std::setw(18) << std::hex << pair.first 
                << std::setw(8) << std::dec << pair.second 
                << std::setw(30) << info.routine_name 
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
    // std::cout << "CALL instruction at: 0x" << std::hex << call_address << ", will return to: 0x" << std::hex << return_address << std::endl;
    tdata->call_stack.push(make_pair(call_address, return_address));
}

// Analysis routine for returns
VOID HandleReturn(THREADID threadid, ADDRINT rsp) {
    ThreadData* tdata = GetThreadData(threadid);
    ADDRINT return_address;

    if (PIN_SafeCopy(&return_address, (VOID *)rsp, sizeof(ADDRINT)) == sizeof(ADDRINT)) {
        if (!tdata->call_stack.empty()) {
            stack<pair<ADDRINT, ADDRINT> > temp_stack;
            // pair<ADDRINT, ADDRINT> initial_top = tdata->call_stack.top();
            bool match_found = false;

            for (int i = 0; i < MAX_STACK_CHECK_DEPTH && !tdata->call_stack.empty(); i++) {
                pair<ADDRINT, ADDRINT> stack_top = tdata->call_stack.top();
                if (stack_top.second == return_address) {
                    // std::cout<<"Matched: "<<std::hex<<stack_top.first<<", "<<stack_top.second<<", "<<return_address<<", "<<address_map[stack_top.first].routine_name <<std::endl;
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
                pair<ADDRINT, ADDRINT> stack_top = tdata->call_stack.top();
                tdata->mismatches[stack_top.first]++;
                std::cout << "Mismatch detected! Call address: 0x" << std::hex << stack_top.first
                        << ", Expected return address: 0x" << stack_top.second
                        << ", Actual return address: 0x" << return_address 
                        // << ", Routine: " << address_map[stack_top.first].routine_name 
                        // << ", Image: " << address_map[stack_top.first].image_name 
                        // << ", Section: " << address_map[stack_top.first].section_name 
                        // << ", Offset: 0x" << address_map[stack_top.first].offset
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

    // std::cout << "Recorded: Address 0x" << std::hex << address 
    //           << ", Image: " << image_name 
    //           << ", Section: " << section_name 
    //           << ", Offset: 0x" << offset 
    //           << ", Routine: " << routine_name << std::endl;
}

VOID Routine(RTN rtn, VOID* v) {
    if (RTN_Valid(rtn)) {
        PIN_LockClient();
        ADDRINT rtn_address = RTN_Address(rtn);
        std::string rtn_name = RTN_Name(rtn);
        // std::cout<<"Routine Address: "<< std::hex << rtn_address<< ", Routine Name: "<<rtn_name<<std::endl;
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
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)HandleReturn, IARG_THREAD_ID, IARG_REG_VALUE, REG_STACK_PTR, IARG_END);
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

    // ThreadData* tdata = new ThreadData();
    // PIN_SetThreadData(tls_key, tdata, 0);
    // std::cout << "Initialized ThreadData for thread 0" << std::endl;

    OutFile.open(KnobOutputFile.Value().c_str());

    INS_AddInstrumentFunction(Instruction, 0);
    RTN_AddInstrumentFunction(Routine, 0);
    PIN_AddThreadStartFunction(ThreadStart, nullptr);
    PIN_AddThreadFiniFunction(ThreadFini, nullptr);
    PIN_AddFiniFunction(Fini, 0);
 
    PIN_StartProgram();

    return 0;
}
