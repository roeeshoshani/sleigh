SLEIGH_SRC_NAMES := slgh_compile xml slghsymbol grammar pcodeparse slghparse slghscan ruleparse slghpatexpress slghpattern slaformat marshal opcodes translate space pcoderaw address float compression crc32 context semantics globalcontext pcodecompile type database variable cover varnode jumptable emulateutil emulate opbehavior memstate override fspec modelrules cpool architecture prefersplit funcdata_op op heritage rangeutil block funcdata merge funcdata_varnode unionresolve dynamic userop pcodeinject typeop varmap stringmanage flow funcdata_block action transform coreaction constseq subflow double condexe blockaction ruleaction multiprecision options printc ifacedecomp interface capability testfunction callgraph graph paramid printlanguage prettyprint comment loadimage cast sleighbase filemanage

SLEIGH_SRCS := $(SLEIGH_SRC_NAMES:%=sleigh/%.cpp)

SRCS := $(SLEIGH_SRCS)
OBJS := $(SRCS:%.cpp=build/%.o)

CXXFLAGS :=
LDFLAGS := -lz

YACC=bison

build/main.elf: $(OBJS)
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -o $@

build/%.o: %.cpp
	@mkdir -p $(@D)
	$(CXX) -c $(CXXFLAGS) $< -o $@

sleigh/grammar.cpp: sleigh/grammar.y
	$(YACC) -l -o $@ $<
sleigh/xml.cpp: sleigh/xml.y
	$(YACC) -l -o $@ $<
sleigh/pcodeparse.cpp: sleigh/pcodeparse.y
	$(YACC) -l -o $@ $<
sleigh/slghparse.cpp: sleigh/slghparse.y
	$(YACC) -l -d -o $@ $<
sleigh/slghscan.cpp: sleigh/slghscan.l
	$(LEX) -L -o$@ $<
sleigh/ruleparse.cpp: sleigh/ruleparse.y
	$(YACC) -p ruleparse -d -o $@ $<

sleigh/slghparse.hh: sleigh/slghparse.y sleigh/slghparse.cpp
sleigh/slghscan.cpp: sleigh/slghparse.hh sleigh/slgh_compile.hh
sleigh/ruleparse.hh: sleigh/ruleparse.y sleigh/ruleparse.cpp

.phony: clean
clean:
	rm -rf build
