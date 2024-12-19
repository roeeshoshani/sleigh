BUILD_DIR ?= build

SRC_NAMES := xml slghsymbol grammar pcodeparse slghparse slghscan ruleparse slghpatexpress slghpattern slaformat marshal opcodes translate space pcoderaw address float compression crc32 context semantics globalcontext pcodecompile type database variable cover varnode jumptable emulateutil emulate opbehavior memstate override fspec modelrules cpool architecture prefersplit funcdata_op op heritage rangeutil block funcdata merge funcdata_varnode unionresolve dynamic userop pcodeinject typeop varmap stringmanage flow funcdata_block action transform coreaction constseq subflow double condexe blockaction ruleaction multiprecision options printc ifacedecomp interface capability testfunction callgraph graph paramid printlanguage prettyprint comment loadimage cast sleighbase filemanage

OBJS := $(SRC_NAMES:%=$(BUILD_DIR)/%.o)

CXXFLAGS := -O3
LDFLAGS := -lz

YACC=bison

.phony: all
all: $(BUILD_DIR)/libsla.a $(BUILD_DIR)/slgh_compile.elf

$(BUILD_DIR)/libsla.a: $(OBJS)
	$(AR) crs $@ $^

$(BUILD_DIR)/slgh_compile.elf: $(BUILD_DIR)/slgh_compile.o $(OBJS)
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

$(BUILD_DIR)/%.o: src/%.cpp
	@mkdir -p $(@D)
	$(CXX) -c $(CXXFLAGS) $< -o $@

src/grammar.cpp: src/grammar.y
	$(YACC) -l -o $@ $<
src/xml.cpp: src/xml.y
	$(YACC) -l -o $@ $<
src/pcodeparse.cpp: src/pcodeparse.y
	$(YACC) -l -o $@ $<
src/slghparse.cpp: src/slghparse.y
	$(YACC) -l -d -o $@ $<
src/slghscan.cpp: src/slghscan.l
	$(LEX) -L -o$@ $<
src/ruleparse.cpp: src/ruleparse.y
	$(YACC) -p ruleparse -d -o $@ $<

src/slghparse.hh: src/slghparse.y src/slghparse.cpp
src/slghscan.cpp: src/slghparse.hh src/slgh_compile.hh
src/ruleparse.hh: src/ruleparse.y src/ruleparse.cpp

.phony: clean
clean:
	rm -rf build
