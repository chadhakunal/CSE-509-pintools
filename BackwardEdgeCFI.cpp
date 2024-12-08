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
using std::stack;
using std::vector;

TLS_KEY tls_key;

typedef struct RtnInfo
{
    string name;
    string image;
} RTN_INFO;

struct ThreadData {
    stack<ADDRINT> call_stack;
    unordered_map<ADDRINT, UINT64> mismatches;
    unordered_map<ADDRINT, RTN_INFO*> addr_to_routine_map;
};

ofstream OutFile;

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "outputs/backward_edge_cfi.out", "specify output file name"); 

const char* StripPath(const char* path)
{
    const char* file = strrchr(path, '/');
    return file ? file + 1 : path;
}

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

    // Log mismatches for this thread
    PIN_LockClient();
    OutFile.setf(ios::showbase);
    OutFile << "Thread " << threadid << " mismatches:" << std::endl;
    for (const auto& pair : tdata->mismatches) {
        OutFile << "  Mismatch at return address: 0x" << std::hex << pair.first
                << "(Routine Name: " << (tdata->addr_to_routine_map[pair.first] ? tdata->addr_to_routine_map[pair.first]->name : "Not found!") << "), Count: " << std::dec << pair.second << std::endl;
    }

    for (const auto& entry : tdata->addr_to_routine_map)
    {
        if(entry.second) {
            OutFile << "Address: 0x" << std::hex << entry.first << " Name: " << std::dec << entry.second->name
                << " Image: " << entry.second->image << endl;
        } else {
            OutFile << "Address: 0x" << std::hex << entry.first << " Empty routine!" << endl;
        }
    }
    PIN_UnlockClient();

    delete tdata;
    std::cout << "Thread " << threadid << " finished." << std::endl;
}

// Analysis routine for calls
VOID HandleCall(THREADID threadid, ADDRINT call_address, ADDRINT return_address) {
    ThreadData* tdata = GetThreadData(threadid);
    // std::cout << "CALL instruction at: 0x" << std::hex << call_address << ", will return to: 0x" << std::hex << return_address << std::endl;
    tdata->call_stack.push(return_address);
}

// Analysis routine for returns
VOID HandleReturn(THREADID threadid, ADDRINT rsp) {
    ThreadData* tdata = GetThreadData(threadid);
    ADDRINT return_address;

    if (PIN_SafeCopy(&return_address, (VOID *)rsp, sizeof(ADDRINT)) == sizeof(ADDRINT)) {
        if (!tdata->call_stack.empty()) {
            vector<ADDRINT> temp_stack; // Temporary stack to store unmatched entries
            bool match_found = false;

            for (int i = 0; i < 4 && !tdata->call_stack.empty(); ++i) {
                ADDRINT stack_top = tdata->call_stack.top();
                tdata->call_stack.pop();

                if (stack_top == return_address) {
                    // std::cout << "Matched! Return address: 0x" << std::hex << return_address << ", Stack Top: 0x" << std::hex << stack_top << std::endl;
                    match_found = true;
                    break;
                } else {
                    temp_stack.push_back(stack_top);
                }
            }

            if (match_found) {
                temp_stack.clear();
            } else {
                for (auto it = temp_stack.rbegin(); it != temp_stack.rend(); ++it) {
                    tdata->call_stack.push(*it);
                }

                // Log the mismatch
                tdata->mismatches[return_address]++;
                std::cout << "Mismatch detected! Return address: 0x" << std::hex << return_address << std::endl;
            }
        } else {
            std::cout << "Warning: Return without corresponding call!" << std::endl;
        }
    } else {
        std::cout << "Failed to read return address from stack!" << std::endl;
    }
}

VOID Instruction(INS ins, VOID *v) {
    // Instrument CALL instructions
    if (INS_IsCall(ins))
    {
        ADDRINT call_address = INS_Address(ins);
        ADDRINT return_address = call_address + INS_Size(ins);

        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)HandleCall, IARG_THREAD_ID, IARG_ADDRINT, call_address, IARG_ADDRINT, return_address, IARG_END);
    }

    // Instrument RET instructions
    else if (INS_IsRet(ins))
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)HandleReturn, IARG_THREAD_ID, IARG_REG_VALUE, REG_STACK_PTR, IARG_END);
    }
}

VOID Routine(RTN rtn, VOID* v) {
    RTN_Open(rtn);

    // Retrieve thread-local data
    THREADID threadid = PIN_ThreadId();
    ThreadData* tdata = GetThreadData(threadid);

    if (tdata == nullptr) {
        std::cout << "ThreadData is null for thread " << threadid << std::endl;
        return;
    }

    // Populate the address-to-routine map for this thread
    ADDRINT rtn_address = RTN_Address(rtn);
    string rtn_name = RTN_Name(rtn);
    string rtn_image = StripPath(IMG_Name(SEC_Img(RTN_Sec(rtn))).c_str());
    // OutFile << "Routine loaded: 0x" << std::hex << rtn_address << " " << rtn_name << " from " << rtn_image << std::endl;

    PIN_LockClient();
    RTN_INFO* rtn_info = new RTN_INFO{rtn_name, rtn_image};
    if (rtn_info == nullptr) {
        std::cout << "RTN_INFO is null for routine at address 0x" << std::hex << rtn_address << std::endl;
        return;
    }
    std::cout<<"Routine: "<<rtn_info->name<<" from "<<rtn_info->image<<std::endl;
    tdata->addr_to_routine_map.insert({{rtn_address, rtn_info}}); //{rtn_name, rtn_image};
    PIN_UnlockClient();

    RTN_Close(rtn);
}

// This function is called when the application exits
VOID Fini(INT32 code, VOID* v) {
    OutFile.close();
}

INT32 Usage() {
    cerr << "This tool implements Backward Edge CFI" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

int main(int argc, char *argv[]) {
    if (PIN_Init(argc, argv)) return Usage();

    tls_key = PIN_CreateThreadDataKey(nullptr); 

    ThreadData* tdata = new ThreadData();
    PIN_SetThreadData(tls_key, tdata, 0);
    std::cout << "Initialized ThreadData for thread 0" << std::endl;

    OutFile.open(KnobOutputFile.Value().c_str());

    INS_AddInstrumentFunction(Instruction, 0);
    RTN_AddInstrumentFunction(Routine, nullptr);
    PIN_AddThreadStartFunction(ThreadStart, nullptr);
    PIN_AddThreadFiniFunction(ThreadFini, nullptr);
    PIN_AddFiniFunction(Fini, 0);
 
    PIN_StartProgram();

    return 0;
}