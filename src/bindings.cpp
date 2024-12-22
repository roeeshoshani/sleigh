#include "error.hh"
#include "globalcontext.hh"
#include "loadimage.hh"
#include "marshal.hh"
#include "opcodes.hh"
#include "pcoderaw.hh"
#include "slaformat.hh"
#include "sleigh.hh"
#include "slghsymbol.hh"
#include "space.hh"
#include "translate.hh"
#include "types.h"
#include "xml.hh"
#include <algorithm>
#include <stdexcept>

using namespace ghidra;

enum class BindingsError {
    Success = 0,
    AddrWraparound = 1,
    AddrOutOfBufferBounds = 2,
    PcodeEmitterReused = 3,
    OutOfMem = 4,
    ParseError = 5,
    Unknown = 6,
};

class BindingsException : public std::exception {
  public:
    BindingsException(BindingsError error) : m_error(error) {}
    BindingsError m_error;
};

class BufLoadImage : public LoadImage {
  public:
    const uint1* m_data;
    size_t m_len;
    uintb m_addr;

    BufLoadImage(const uint1* data, size_t len, uintb addr) : LoadImage("[memory]"), m_data(data), m_len(len), m_addr(addr) {
        // check for address wraparound
        if (m_addr + (uintb)m_len < m_addr) {
            throw BindingsException(BindingsError::AddrWraparound);
        }
    }

    uintb startAddr() const { return m_addr; }
    uintb endAddr() const { return m_addr + m_len; }

    virtual void loadFill(uint1* ptr, int4 size, const Address& addr) {
        uintb start_addr = addr.getOffset();
        uintb end_addr = start_addr + (uintb)size;

        // check for address wraparound
        if (end_addr < start_addr) {
            throw BindingsException(BindingsError::AddrWraparound);
        }

        // make sure that the address is within our bounds
        if (start_addr < startAddr()) {
            throw BindingsException(BindingsError::AddrOutOfBufferBounds);
        }

        for (uintb cur_addr = start_addr; cur_addr < end_addr; cur_addr++) {
            uintb off = cur_addr - start_addr;
            if (cur_addr >= endAddr()) {
                // address is beyond the bounds of the buffer, return 0
                ptr[off] = 0;
            } else {
                // address is inside the buffer, return the byte value
                ptr[off] = m_data[off];
            }
        }
    }
    virtual string getArchType(void) const { return "[memory]"; }
    virtual void adjustVma(long adjust) {}
};

class MemoryBuffer : public std::streambuf {
  public:
    MemoryBuffer(const uint1* data, size_t len) {
        setg((char*)const_cast<uint1*>(data), (char*)const_cast<uint1*>(data), (char*)const_cast<uint1*>(data) + len);
    }
};

struct BindingsInsn {
    OpCode m_opcode;

    bool m_has_out_var;
    VarnodeData m_out_var;

    size_t m_in_vars_amount;
    VarnodeData* m_in_vars;

    size_t m_machine_insn_len;

    ~BindingsInsn() {
        if (m_in_vars != nullptr) {
            delete[] m_in_vars;
            m_in_vars = nullptr;
        }
    }
};

class BindingsSleigh : public SleighBase {
  public:
    BufLoadImage m_buf_load_image;
    ContextInternal m_ctx;
    mutable PcodeCacher m_pcode_cache;
    ContextCache* m_ctx_cache;
    DisassemblyCache* m_dis_cache;
    BindingsInsn m_insn;

    BindingsSleigh(const uint1* sla_content, size_t sla_content_len, const uint1* data, size_t data_len, uintb data_addr)
        : SleighBase(), m_buf_load_image(data, data_len, data_addr), m_ctx(), m_pcode_cache(), m_ctx_cache(nullptr),
          m_dis_cache(nullptr), m_insn() {
        // convert the sla content buffer to an istream
        MemoryBuffer buf(sla_content, sla_content_len);
        std::istream stream(&buf);

        // decode the sla specification
        sla::FormatDecode decoder(this);
        decoder.ingestStream(stream);
        decode(decoder);

        m_ctx_cache = new ContextCache(&m_ctx);

        uint4 parser_cachesize = 2;
        uint4 parser_windowsize = 32;
        if ((maxdelayslotbytes > 1) || (unique_allocatemask != 0)) {
            parser_cachesize = 8;
            parser_windowsize = 256;
        }
        m_dis_cache = new DisassemblyCache(this, m_ctx_cache, getConstantSpace(), parser_cachesize, parser_windowsize);
    }

    ~BindingsSleigh() {
        if (m_ctx_cache != nullptr) {
            delete m_ctx_cache;
        }
        if (m_dis_cache != nullptr) {
            delete m_dis_cache;
        }
    }

    // implement all virtual functions to make compiler happy
    virtual void initialize(DocumentStorage& store) { throw std::runtime_error("not implemented by bindings sleigh instance"); }
    virtual int4 oneInstruction(PcodeEmit& emit, const Address& baseaddr) const {
        throw std::runtime_error("not implemented by bindings sleigh instance");
    }
    virtual int4 instructionLength(const Address& baseaddr) const {
        throw std::runtime_error("not implemented by bindings sleigh instance");
    }
    virtual int4 printAssembly(AssemblyEmit& emit, const Address& baseaddr) const {
        throw std::runtime_error("not implemented by bindings sleigh instance");
    }

    void resolve(ParserContext& pos)

    {
        m_buf_load_image.loadFill(pos.getBuffer(), 16, pos.getAddr());
        ParserWalkerChange walker(&pos);
        pos.deallocateState(walker); // Clear the previous resolve and initialize the walker
        Constructor *ct, *subct;
        uint4 off;
        int4 oper, numoper;

        pos.setDelaySlot(0);
        walker.setOffset(0);        // Initial offset
        pos.clearCommits();         // Clear any old context commits
        pos.loadContext();          // Get context for current address
        ct = root->resolve(walker); // Base constructor
        walker.setConstructor(ct);
        ct->applyContext(walker);
        while (walker.isState()) {
            ct = walker.getConstructor();
            oper = walker.getOperand();
            numoper = ct->getNumOperands();
            while (oper < numoper) {
                OperandSymbol* sym = ct->getOperand(oper);
                off = walker.getOffset(sym->getOffsetBase()) + sym->getRelativeOffset();
                pos.allocateOperand(oper, walker); // Descend into new operand and reserve space
                walker.setOffset(off);
                TripleSymbol* tsym = sym->getDefiningSymbol();
                if (tsym != (TripleSymbol*)0) {
                    subct = tsym->resolve(walker);
                    if (subct != (Constructor*)0) {
                        walker.setConstructor(subct);
                        subct->applyContext(walker);
                        break;
                    }
                }
                walker.setCurrentLength(sym->getMinimumLength());
                walker.popOperand();
                oper += 1;
            }
            if (oper >= numoper) { // Finished processing constructor
                walker.calcCurrentLength(ct->getMinimumLength(), numoper);
                walker.popOperand();
                // Check for use of delayslot
                ConstructTpl* templ = ct->getTempl();
                if ((templ != (ConstructTpl*)0) && (templ->delaySlot() > 0))
                    pos.setDelaySlot(templ->delaySlot());
            }
        }
        pos.setNaddr(pos.getAddr() + pos.getLength()); // Update Naddr to pointer after instruction
        pos.setParserState(ParserContext::disassembly);
    }

    void resolveHandles(ParserContext& pos) const

    {
        TripleSymbol* triple;
        Constructor* ct;
        int4 oper, numoper;

        ParserWalker walker(&pos);
        walker.baseState();
        while (walker.isState()) {
            ct = walker.getConstructor();
            oper = walker.getOperand();
            numoper = ct->getNumOperands();
            while (oper < numoper) {
                OperandSymbol* sym = ct->getOperand(oper);
                walker.pushOperand(oper); // Descend into node
                triple = sym->getDefiningSymbol();
                if (triple != (TripleSymbol*)0) {
                    if (triple->getType() == SleighSymbol::subtable_symbol)
                        break;
                    else // Some other kind of symbol as an operand
                        triple->getFixedHandle(walker.getParentHandle(), walker);
                } else { // Must be an expression
                    PatternExpression* patexp = sym->getDefiningExpression();
                    intb res = patexp->getValue(walker);
                    FixedHandle& hand(walker.getParentHandle());
                    hand.space = pos.getConstSpace(); // Result of expression is a constant
                    hand.offset_space = (AddrSpace*)0;
                    hand.offset_offset = (uintb)res;
                    hand.size = 0; // This size should not get used
                }
                walker.popOperand();
                oper += 1;
            }
            if (oper >= numoper) { // Finished processing constructor
                ConstructTpl* templ = ct->getTempl();
                if (templ != (ConstructTpl*)0) {
                    HandleTpl* res = templ->getResult();
                    if (res != (HandleTpl*)0) // Pop up handle to containing operand
                        res->fix(walker.getParentHandle(), walker);
                    // If we need an indicator that the constructor exports nothing try
                    // else
                    //   walker.getParentHandle().setInvalid();
                }
                walker.popOperand();
            }
        }
        pos.setParserState(ParserContext::pcode);
    }

    ParserContext* obtainContext(const Address& addr, int4 state) {
        ParserContext* pos = m_dis_cache->getParserContext(addr);
        int4 curstate = pos->getParserState();
        if (curstate >= state)
            return pos;
        if (curstate == ParserContext::uninitialized) {
            resolve(*pos);
            if (state == ParserContext::disassembly)
                return pos;
        }
        // If we reach here,  state must be ParserContext::pcode
        resolveHandles(*pos);
        return pos;
    }

    int4 myOneInstruction(PcodeEmit& emit, uintb address) {
        Address baseaddr(getDefaultCodeSpace(), address);
        if (alignment != 1) {
            if ((baseaddr.getOffset() % alignment) != 0) {
                ostringstream s;
                s << "Instruction address not aligned: " << baseaddr;
                throw UnimplError(s.str(), 0);
            }
        }

        ParserContext* pos = obtainContext(baseaddr, ParserContext::pcode);
        pos->applyCommits();
        int4 fallOffset = pos->getLength();

        if (pos->getDelaySlot() > 0) {
            int4 bytecount = 0;
            do {
                // Do not pass pos->getNaddr() to obtainContext, as pos may have been previously cached and had naddr adjusted
                ParserContext* delaypos = obtainContext(pos->getAddr() + fallOffset, ParserContext::pcode);
                delaypos->applyCommits();
                int4 len = delaypos->getLength();
                fallOffset += len;
                bytecount += len;
            } while (bytecount < pos->getDelaySlot());
            pos->setNaddr(pos->getAddr() + fallOffset);
        }
        ParserWalker walker(pos);
        walker.baseState();
        m_pcode_cache.clear();
        SleighBuilder builder(&walker, m_dis_cache, &m_pcode_cache, getConstantSpace(), getUniqueSpace(), unique_allocatemask);
        try {
            builder.build(walker.getConstructor()->getTempl(), -1);
            m_pcode_cache.resolveRelatives();
            m_pcode_cache.emit(baseaddr, &emit);
        } catch (UnimplError& err) {
            ostringstream s;
            s << "Instruction not implemented in pcode:\n ";
            ParserWalker* cur = builder.getCurrentWalker();
            cur->baseState();
            Constructor* ct = cur->getConstructor();
            cur->getAddr().printRaw(s);
            s << ": ";
            ct->printMnemonic(s, *cur);
            s << "  ";
            ct->printBody(s, *cur);
            err.explain = s.str();
            err.instruction_length = fallOffset;
            throw err;
        }
        return fallOffset;
    }
};

class BindingsPcodeEmitter : public PcodeEmit {
  public:
    bool m_already_initialized;
    OpCode m_opcode;
    VarnodeData m_out_var;
    bool m_has_out_var;
    VarnodeData* m_in_vars;
    size_t m_in_vars_amount;

    BindingsPcodeEmitter()
        : m_already_initialized(false), m_opcode(), m_out_var(), m_has_out_var(false), m_in_vars(nullptr), m_in_vars_amount(0) {
    }

    virtual ~BindingsPcodeEmitter(void) {
        if (m_in_vars != nullptr) {
            delete[] m_in_vars;
            m_in_vars = nullptr;
        }
    }

    BindingsInsn takeInsn(size_t machine_insn_len) {
        BindingsInsn insn = {
            .m_opcode = m_opcode,
            .m_has_out_var = m_has_out_var,
            .m_out_var = m_out_var,
            .m_in_vars_amount = m_in_vars_amount,
            .m_in_vars = m_in_vars,
            .m_machine_insn_len = machine_insn_len
        };

        // ownership moved to insn
        m_in_vars = nullptr;

        return std::move(insn);
    }

    void reset() {
        m_has_out_var = false;

        m_in_vars_amount = 0;
        if (m_in_vars != nullptr) {
            delete[] m_in_vars;
            m_in_vars = nullptr;
        }

        m_already_initialized = false;
    }

    virtual void dump(const Address& addr, OpCode opc, VarnodeData* outvar, VarnodeData* vars, int4 isize) {
        if (m_already_initialized) {
            throw BindingsException(BindingsError::PcodeEmitterReused);
        }

        m_opcode = opc;

        if (outvar != nullptr) {
            m_has_out_var = true;
            m_out_var = *outvar;
        }

        if (isize > 0) {
            m_in_vars_amount = isize;
            m_in_vars = new VarnodeData[m_in_vars_amount];
            if (m_in_vars == nullptr) {
                throw BindingsException(BindingsError::OutOfMem);
            }
            for (size_t i = 0; i < m_in_vars_amount; i++) {
                m_in_vars[i] = vars[i];
            }
        }
        m_already_initialized = true;
    }
};

#define HANDLE_EXCEPTIONS()                                                                                                    \
    catch (BindingsException & e) {                                                                                            \
        return (int)e.m_error;                                                                                                 \
    }                                                                                                                          \
    catch (ParseError&) {                                                                                                      \
        return (int)BindingsError::ParseError;                                                                                 \
    }                                                                                                                          \
    catch (...) {                                                                                                              \
        return (int)BindingsError::Unknown;                                                                                    \
    }

extern "C" {

int sleigh_bindings_ctx_init(
    const uint8_t* sla_content, size_t sla_content_len, const uint8_t* data, size_t data_len, uint64_t data_addr, void** ctx
) {
    try {
        BindingsSleigh* s = new BindingsSleigh(sla_content, sla_content_len, data, data_len, data_addr);
        if (s == nullptr) {
            return (int)BindingsError::OutOfMem;
        }
        *ctx = s;
        return (int)BindingsError::Success;
    }
    HANDLE_EXCEPTIONS();
}

int sleigh_bindings_ctx_lift_one(void* ctx, uint64_t addr) {
    try {
        BindingsSleigh* s = (BindingsSleigh*)ctx;
        BindingsPcodeEmitter emitter;
        uint32_t machine_insn_len = s->myOneInstruction(emitter, addr);
        s->m_insn = emitter.takeInsn(machine_insn_len);
        return (int)BindingsError::Success;
    }
    HANDLE_EXCEPTIONS();
}

int sleigh_bindings_ctx_insn_opcode(void* ctx) {
    BindingsSleigh* s = (BindingsSleigh*)ctx;
    return s->m_insn.m_opcode;
}

void* sleigh_bindings_ctx_insn_out_var(void* ctx) {
    BindingsSleigh* s = (BindingsSleigh*)ctx;
    if (!s->m_insn.m_has_out_var) {
        return nullptr;
    }
    return &s->m_insn.m_out_var;
}

size_t sleigh_bindings_ctx_insn_in_vars_amount(void* ctx) {
    BindingsSleigh* s = (BindingsSleigh*)ctx;
    return s->m_insn.m_in_vars_amount;
}

void* sleigh_bindings_ctx_insn_in_var(void* ctx, size_t index) {
    BindingsSleigh* s = (BindingsSleigh*)ctx;
    if (index >= s->m_insn.m_in_vars_amount) {
        return nullptr;
    }
    return &s->m_insn.m_in_vars[index];
}

uint64_t sleigh_bindings_varnode_offset(void* varnode) {
    VarnodeData* v = (VarnodeData*)varnode;
    return v->offset;
}

uint32_t sleigh_bindings_varnode_size(void* varnode) {
    VarnodeData* v = (VarnodeData*)varnode;
    return v->size;
}

void* sleigh_bindings_varnode_space(void* varnode) {
    VarnodeData* v = (VarnodeData*)varnode;
    return v->space;
}

const char* sleigh_bindings_space_name(void* space) {
    AddrSpace* s = (AddrSpace*)space;
    return s->getName().c_str();
}

int sleigh_bindings_space_type(void* space) {
    AddrSpace* s = (AddrSpace*)space;
    return s->getType();
}

uint32_t sleigh_bindings_space_word_size(void* space) {
    AddrSpace* s = (AddrSpace*)space;
    return s->getWordSize();
}

uint32_t sleigh_bindings_space_addr_size(void* space) {
    AddrSpace* s = (AddrSpace*)space;
    return s->getAddrSize();
}

void sleigh_bindings_ctx_destroy(void* ctx) {
    BindingsSleigh* s = (BindingsSleigh*)ctx;
    delete s;
}
}
